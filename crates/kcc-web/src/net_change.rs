//! What the actions of the network pages share: the region read back after a change, and
//! the reading of router values.

use core::net::Ipv4Addr;

use fluent_bundle::FluentArgs;
use kcc_app::workflow::CliChangeRequest;
use kcc_domain::{DomainError, RouterCtx};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use kcc_rci::ObjectName;
use serde_json::Value;

use crate::{
    WebState,
    authz::CurrentUser,
    markup::Rendered,
    net_interfaces, net_internet, net_mesh,
    net_pages::{Call, Tab},
    net_wifi,
    page_kit::{
        action::Action,
        context,
        facts::RouterFacts,
        family::Family,
        outcome::Outcome,
        read_failure::{ReadProblem, domain_problem},
        request::with_query,
        respond,
        respond::Answer,
    },
};

/// The object a dialog or a change is about, in the reader's language.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Subject<'call> {
    /// Router profile id.
    router: &'call str,
    /// The object's name.
    name: &'call ObjectName,
    /// The reader's locale.
    locale: Locale,
}

impl<'call> Subject<'call> {
    /// `name` on `router`, read in `locale`.
    pub(crate) const fn new(router: &'call str, name: &'call ObjectName, locale: Locale) -> Self {
        Self {
            router,
            name,
            locale,
        }
    }

    /// The reader's locale.
    pub(crate) const fn locale(self) -> Locale {
        self.locale
    }

    /// The page action `action` (such as `internet/address`) naming the object, with
    /// `extra` parameters after the name.
    pub(crate) fn url(self, action: &str, extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![("name", self.name.as_str())];
        pairs.extend_from_slice(extra);
        with_query(&format!("/ui/r/{}/{action}", self.router), &pairs)
    }

    /// `key` in the reader's language, with the object's name as `$name`.
    pub(crate) fn title(self, key: MessageKey) -> String {
        let mut args = FluentArgs::new();
        args.set("name", self.name.as_str().to_owned());
        tr(self.locale, key, Some(&args))
    }

    /// `key` in the reader's language.
    pub(crate) fn text(self, key: MessageKey) -> String {
        tr(self.locale, key, None)
    }
}

/// The router of a read-only dialog: its catalog facts and the context to read with.
///
/// # Errors
///
/// Answers the bare status when the router is not visible, and the failure in the page's
/// outcome region when it cannot be used now.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn reader(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
) -> Result<(RouterFacts, RouterCtx), Answer> {
    let target = context::target(state, user, router)
        .await
        .map_err(|refusal| Answer::from(refusal.status()))?;
    target
        .context(state)
        .await
        .map_err(|error| unusable(user.locale(), &error.problem(Family::Changes)))
}

/// A router that could not be read, answered with `problem` in the page's outcome region.
pub(crate) fn unusable(locale: Locale, problem: &ReadProblem) -> Answer {
    let failure = problem.failure(locale, "unreachable");
    respond::retarget(Outcome::failed(failure).render(locale), "#page-outcome").into()
}

/// A dialog whose router read failed with `error`: the failure in the page's outcome
/// region instead of a form filled in from nothing.
pub(crate) fn unread(locale: Locale, error: &DomainError) -> Answer {
    tracing::warn!(%error, "network page: router read failed");
    unusable(locale, &domain_problem(error))
}

/// Ends `action` because the router read its change is checked against failed with
/// `error`: audited `unreachable`, the failure shown in the page's outcome region, nothing
/// planned.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn unread_change(action: Action<'_>, error: &DomainError) -> Answer {
    let locale = action.locale();
    action.abandon("unreachable").await;
    unread(locale, error)
}

/// The region of the page of `call`, read back from the router of `domain` after a
/// change.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn refreshed(call: Call<'_>, domain: &RouterCtx) -> Option<Rendered> {
    match call.tab() {
        Tab::Interfaces => net_interfaces::refreshed(call, domain).await,
        Tab::Internet => net_internet::refreshed(call, domain).await,
        Tab::Wifi => net_wifi::refreshed(call, domain).await,
        Tab::Mesh => net_mesh::refreshed(call, domain).await,
    }
}

/// The parser requests of one change as one request: their lines in order, every
/// read-back, the first one's permission.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] for no request at all.
pub(crate) fn merged(requests: Vec<CliChangeRequest>) -> Result<CliChangeRequest, DomainError> {
    let mut rest = requests.into_iter();
    let mut first = rest.next().ok_or(DomainError::InvalidResponse)?;
    for request in rest {
        first.commands.extend(request.commands);
        first.verify.extend(request.verify);
    }
    Ok(first)
}

/// A string or a number of a router answer as text; an empty string or any other value is
/// none.
pub(crate) fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => (!text.is_empty()).then(|| text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// `address` with the prefix length of the dotted `mask`, such as `192.0.2.1/24`; the
/// address alone when the mask is missing or not a netmask.
pub(crate) fn with_prefix(address: Option<&str>, mask: Option<&Value>) -> Option<String> {
    let shown = address.filter(|text| !text.is_empty())?;
    let bits = mask
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<Ipv4Addr>().ok())
        .map(|parsed| u32::from(parsed).count_ones());
    Some(match bits {
        Some(prefix) if !shown.contains('/') => format!("{shown}/{prefix}"),
        Some(_) | None => shown.to_owned(),
    })
}
