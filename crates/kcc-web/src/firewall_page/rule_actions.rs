//! The rule actions of the firewall page: Move up, Move down, Disable or Enable, and
//! Remove after a plain confirmation.
//!
//! Every action names its rule by list, position and stored words, and acts only when a
//! fresh read of the router still has that rule at that position.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::firewall::{
    descriptor::DESCRIPTOR,
    lists::{Firewall, ListEntry},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    checks::list_name,
    expect::Expect,
    lines,
    run::{Planned, Sender, find},
    views::Spot,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        request::{Params, missing},
        respond::Answer,
        submit::{Formless, Invalid, rejected::Rejected},
    },
    routing_page::reply::ConfirmDialog,
    system_pages::shared::{merged, value},
};

/// A rule removed, audited as `web.firewall_rule_remove`.
const REMOVE: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_remove");

/// A rule moved, audited as `web.firewall_rule_order`.
const ORDER: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_order");

/// A rule disabled or enabled, audited as `web.firewall_rule_state`.
const STATE: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_state");

/// The rule an action names: its list, position and stored words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Named {
    /// The list.
    list: String,
    /// The position, from 0.
    index: usize,
    /// The stored words.
    words: String,
}

impl Named {
    /// The rule `pairs` name.
    ///
    /// # Errors
    ///
    /// Answers 404 when a part is missing or malformed.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Result<Self, Answer> {
        let list = value(pairs, "list")
            .filter(|name| list_name(name))
            .ok_or_else(missing)?;
        let index = value(pairs, "index")
            .and_then(|text| text.parse::<usize>().ok())
            .ok_or_else(missing)?;
        let words = value(pairs, "rule").ok_or_else(missing)?;
        Ok(Self {
            list: list.to_owned(),
            index,
            words: words.to_owned(),
        })
    }

    /// The list.
    pub(crate) fn list(&self) -> &str {
        &self.list
    }

    /// The position, from 0.
    pub(crate) const fn index(&self) -> usize {
        self.index
    }

    /// The rule in `firewall`, when it still stands at its position.
    pub(crate) fn find<'snapshot>(
        &self,
        firewall: &'snapshot Firewall,
    ) -> Option<&'snapshot ListEntry> {
        firewall
            .list(&self.list)?
            .entry(self.index)
            .filter(|entry| entry.rule().text() == self.words)
    }

    /// The localized title `key` naming the rule's position and list.
    pub(crate) fn title(&self, locale: Locale, key: MessageKey) -> String {
        let mut args = FluentArgs::new();
        args.set("index", self.index.saturating_add(1).to_string());
        args.set("name", self.list.clone());
        tr(locale, key, Some(&args))
    }
}

/// The interfaces whose traffic the list `list` of `firewall` filters.
pub(crate) fn filtered(firewall: &Firewall, list: &str) -> Vec<String> {
    firewall
        .bindings_of(list)
        .map(|binding| binding.interface().to_owned())
        .collect()
}

/// `GET /ui/r/{router}/firewall/rule/remove?list=&index=&rule=`: asks first.
///
/// # Errors
///
/// Answers 404 for a malformed rule, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn remove_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), Vec::new());
    let named = Named::from_pairs(&pairs)?;
    let action = REMOVE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let title = named.title(locale, keys::WEB_FIREWALL_REMOVE_TITLE);
    let url = format!(
        "/ui/r/{router}/firewall/rule/remove?{}",
        query.unwrap_or_default()
    );
    Ok(ConfirmDialog::new(locale, title, keys::WEB_FIREWALL_REMOVE_TEXT, url).show())
}

/// `POST /ui/r/{router}/firewall/rule/remove?...`: removes the rule and reads it back.
///
/// # Errors
///
/// Answers 404 for a malformed rule, 403 for a management change the role may not make,
/// and what the kit answers when the router or the permission is missing.
pub(crate) async fn remove(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let named = Named::from_pairs(&pairs)?;
    let action = REMOVE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::of(pairs.clone());
    let path = format!("/ui/r/{router}/firewall/rule/remove");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &params, Formless)
        .submit_reading(
            async |_params, domain| {
                let (firewall, entry) = find(domain, &named, locale).await?;
                let rule = entry
                    .rule()
                    .form()
                    .ok_or_else(|| Invalid::from(Vec::new()))?;
                let same = |found: &&ListEntry| found.rule().words() == entry.rule().words();
                let count = firewall
                    .list(named.list())
                    .map_or(0, |list| list.entries().iter().filter(same).count());
                Ok(
                    lines::remove_rule(domain, named.list(), rule).map(|request| {
                        let expect = Expect::Count {
                            list: named.list().to_owned(),
                            words: entry.rule().words().to_vec(),
                            count: count.saturating_sub(1),
                        };
                        Planned::new(request, expect, filtered(&firewall, named.list()))
                    }),
                )
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}

/// `POST /ui/r/{router}/firewall/rule/move?list=&index=&rule=&to=`: moves the rule to
/// position `to` and reads the list back.
///
/// # Errors
///
/// Answers 404 for a malformed rule or position, 403 for a management change the role may
/// not make, and what the kit answers when the router or the permission is missing.
pub(crate) async fn move_rule(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let named = Named::from_pairs(&pairs)?;
    let to = value(&pairs, "to")
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or_else(missing)?;
    let action = ORDER.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::of(pairs.clone());
    let path = format!("/ui/r/{router}/firewall/rule/move");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &params, Formless)
        .submit_reading(
            async |_params, domain| {
                let (firewall, entry) = find(domain, &named, locale).await?;
                let size = firewall
                    .list(named.list())
                    .map_or(0, |list| list.entries().len());
                if to >= size || to == named.index() {
                    return Err(Invalid::from(Vec::new()).into());
                }
                Ok(
                    lines::order(domain, named.list(), (&entry.listed(), to)).map(|request| {
                        let expect = Expect::At {
                            list: named.list().to_owned(),
                            position: to,
                            words: entry.rule().words().to_vec(),
                        };
                        Planned::new(request, expect, filtered(&firewall, named.list()))
                    }),
                )
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}

/// `POST /ui/r/{router}/firewall/rule/state?list=&index=&rule=&value=on|off`: enables or
/// disables the rule and reads it back.
///
/// # Errors
///
/// Answers 404 for a malformed rule or value, 403 for a management change the role may
/// not make, and what the kit answers when the router or the permission is missing.
pub(crate) async fn switch(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let named = Named::from_pairs(&pairs)?;
    let enabled = match value(&pairs, "value") {
        Some("on") => true,
        Some("off") => false,
        _ => return Err(missing()),
    };
    let action = STATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::of(pairs.clone());
    let path = format!("/ui/r/{router}/firewall/rule/state");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &params, Formless)
        .submit_reading(
            async |_params, domain| {
                let (firewall, entry) = find(domain, &named, locale).await?;
                let identity = entry.configured().ok_or(Rejected::Missing)?;
                Ok(
                    lines::state(domain, named.list(), (&identity, enabled)).map(|request| {
                        let expect = Expect::Disabled {
                            list: named.list().to_owned(),
                            index: named.index(),
                            disabled: !enabled,
                        };
                        Planned::new(request, expect, filtered(&firewall, named.list()))
                    }),
                )
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}
