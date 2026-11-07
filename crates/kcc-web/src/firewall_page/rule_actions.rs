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
use kcc_domain::{DomainError, RouterCtx, firewall::descriptor::DESCRIPTOR};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    checks::list_name,
    lines,
    run::{Expect, Planned, Sender, submit},
    snapshot::{self, Entry, Snapshot},
    views::Spot,
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::missing,
    page_kit::{
        action::{Action, Operation},
        failure::plan_failure,
        family::Family,
        outcome::{Failure, Outcome},
        respond::Answer,
    },
    routing_page::reply::{ConfirmDialog, answer},
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
        firewall: &'snapshot Snapshot,
    ) -> Option<&'snapshot Entry> {
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

/// The router's firewall and the rule `named`, when it still has it.
///
/// # Errors
///
/// Answers the audited "no longer there" outcome, or why the router could not be read.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn located<'call>(
    action: Action<'call>,
    domain: &RouterCtx,
    named: &Named,
) -> Result<(Action<'call>, Snapshot, Entry), Answer> {
    let locale = action.locale();
    match snapshot::read(domain).await {
        Ok(firewall) => {
            if let Some(entry) = named.find(&firewall).cloned() {
                return Ok((action, firewall, entry));
            }
            action.abandon("gone").await;
            let failure = Failure::new(tr(locale, keys::WEB_ROUTING_GONE, None), "gone");
            Err(answer(Outcome::failed(failure), None, locale).into())
        }
        Err(message) => {
            action.abandon("unreachable").await;
            let failure = Failure::new(tr(locale, message, None), "unreachable");
            Err(answer(Outcome::failed(failure), None, locale).into())
        }
    }
}

/// The interfaces whose traffic the list `list` of `firewall` filters.
pub(crate) fn filtered(firewall: &Snapshot, list: &str) -> Vec<String> {
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
    let opened = REMOVE.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, firewall, entry) = located(opened, &domain, &named).await?;
    let Some(rule) = entry.rule().parsed() else {
        action.abandon("validation_failed").await;
        return Err(missing());
    };
    let same = |found: &&Entry| found.rule().words() == entry.rule().words();
    let count = firewall
        .list(named.list())
        .map_or(0, |list| list.entries().iter().filter(same).count());
    let planned =
        lines::remove_rule(&domain, named.list(), (rule, entry.rule().words())).map(|request| {
            let expect = Expect::Count {
                list: named.list().to_owned(),
                words: entry.rule().words().to_vec(),
                count: count.saturating_sub(1),
            };
            Planned::new(request, expect, filtered(&firewall, named.list()))
        });
    let path = format!("/ui/r/{router}/firewall/rule/remove");
    let sender = Sender::new(&user, &headers, (&path, &pairs));
    finish(action, &domain, planned, sender).await
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
    let opened = ORDER.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, firewall, entry) = located(opened, &domain, &named).await?;
    let size = firewall
        .list(named.list())
        .map_or(0, |list| list.entries().len());
    if to >= size || to == named.index() {
        action.abandon("validation_failed").await;
        return Err(missing());
    }
    let planned = lines::order(&domain, named.list(), (named.index(), to)).map(|request| {
        let expect = Expect::At {
            list: named.list().to_owned(),
            position: to,
            words: entry.rule().words().to_vec(),
        };
        Planned::new(request, expect, filtered(&firewall, named.list()))
    });
    let path = format!("/ui/r/{router}/firewall/rule/move");
    let sender = Sender::new(&user, &headers, (&path, &pairs));
    finish(action, &domain, planned, sender).await
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
    let opened = STATE.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, firewall, _entry) = located(opened, &domain, &named).await?;
    let planned = lines::state(&domain, named.list(), (named.index(), enabled)).map(|request| {
        let expect = Expect::Disabled {
            list: named.list().to_owned(),
            index: named.index(),
            disabled: !enabled,
        };
        Planned::new(request, expect, filtered(&firewall, named.list()))
    });
    let path = format!("/ui/r/{router}/firewall/rule/state");
    let sender = Sender::new(&user, &headers, (&path, &pairs));
    finish(action, &domain, planned, sender).await
}

/// Submits `planned`, or answers why it could not be planned.
///
/// # Errors
///
/// Answers what [`submit`] answers.
// NOT cancel-safe: see `Action::run_with`.
pub(crate) async fn finish(
    action: Action<'_>,
    domain: &RouterCtx,
    planned: Result<Planned, DomainError>,
    sender: Sender<'_>,
) -> Result<Response, Answer> {
    match planned {
        Ok(change) => submit(action, domain, change, (sender, Spot::Lists)).await,
        Err(error) => {
            let locale = action.locale();
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            Ok(answer(Outcome::failed(failure), None, locale))
        }
    }
}
