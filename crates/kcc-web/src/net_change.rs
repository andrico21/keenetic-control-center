//! What the actions of the network pages share: how a planned change runs and is
//! answered, and the reading of router values.

use core::net::Ipv4Addr;

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_app::workflow::CliChangeRequest;
use kcc_catalog::Risk;
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
    net_interfaces, net_internet, net_mesh,
    net_pages::{Call, Tab},
    net_wifi,
    page_kit::{
        action::Action,
        change::Change,
        context,
        facts::RouterFacts,
        failure::plan_failure,
        family::Family,
        outcome::{Failure, Outcome},
        request::with_query,
        respond,
        respond::{Answer, changed},
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
// cancel-safe: reads only.
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
        .map_err(|error| unusable(user.locale(), error.message(Family::Changes)))
}

/// A router that could not be read, answered with `message` in the page's outcome region.
pub(crate) fn unusable(locale: Locale, message: MessageKey) -> Answer {
    let failure = Failure::new(tr(locale, message, None), "unreachable");
    respond::retarget(Outcome::failed(failure).render(locale), "#page-outcome").into()
}

/// A change planned on the router of `domain`, or why it could not be planned.
pub(crate) struct Planned {
    /// The router to read back from.
    domain: RouterCtx,
    /// The parser request and its risk.
    change: Result<(CliChangeRequest, Risk), DomainError>,
}

impl Planned {
    /// `change`, planned on the router of `domain`.
    pub(crate) const fn new(
        domain: RouterCtx,
        change: Result<(CliChangeRequest, Risk), DomainError>,
    ) -> Self {
        Self { domain, change }
    }
}

/// Runs a planned change and answers with its outcome and, after a success, the region of
/// the page of `call` read back; a change that could not be planned is answered with why.
// NOT cancel-safe: see `Action::run`.
pub(crate) async fn finish(call: Call<'_>, action: Action<'_>, planned: Planned) -> Response {
    let locale = action.locale();
    let (request, risk) = match planned.change {
        Ok(found) => found,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return changed(Outcome::failed(failure), None, None, locale);
        }
    };
    let outcome = action.run(risk, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        match call.tab() {
            Tab::Interfaces => net_interfaces::refreshed(call, &planned.domain).await,
            Tab::Internet => net_internet::refreshed(call, &planned.domain).await,
            Tab::Wifi => net_wifi::refreshed(call, &planned.domain).await,
            Tab::Mesh => net_mesh::refreshed(call, &planned.domain).await,
        }
    } else {
        None
    };
    changed(outcome, refreshed, None, locale)
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
