//! The one-field dialogs of a connection on the internet page.
//!
//! They change the user name, the underlying connection, the MTU and the priority, each
//! checked before anything is sent and planned with the WAN domain.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{ChangeOp, DomainError, RouterCtx, wan};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Subject, refreshed},
    net_form::{Choice, FormDialog, Input},
    net_pages::{Call, Tab},
    net_wan::{Kind, Link, links},
    page_kit::{
        action::Operation,
        change::Change,
        request::{Params, missing},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// The user name, audited as `web.wan_identity`.
const IDENTITY: Operation = Operation::write(&wan::DESCRIPTOR, "identity", "web.wan_identity");

/// The underlying connection, audited as `web.wan_connect_via`.
const VIA: Operation = Operation::write(&wan::DESCRIPTOR, "connect_via", "web.wan_connect_via");

/// The MTU, audited as `web.wan_mtu`.
const MTU: Operation = Operation::write(&wan::DESCRIPTOR, "mtu", "web.wan_mtu");

/// The priority, audited as `web.wan_priority`.
const PRIORITY: Operation = Operation::write(&wan::DESCRIPTOR, "priority", "web.wan_priority");

/// Longest user name accepted, in characters.
const IDENTITY_CHARS: usize = 64;

/// Smallest MTU accepted.
const MTU_MIN: i64 = 576;

/// Largest MTU accepted.
const MTU_MAX: i64 = 1_500;

/// Largest priority accepted.
const PRIORITY_MAX: i64 = 0xFFFF;

/// A setting changed in its own dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setting {
    /// The PPP user name.
    Identity,
    /// The connection a tunnel runs over.
    Via,
    /// The MTU.
    Mtu,
    /// The priority.
    Priority,
}

/// A value the dialog of its setting accepted.
enum Checked {
    /// A user name.
    Identity(String),
    /// An underlying connection.
    Via(ObjectName),
    /// An MTU.
    Mtu(i64),
    /// A priority.
    Priority(i64),
}

impl Setting {
    /// The setting named by the route segment `slug`.
    fn from_slug(slug: &str) -> Option<Self> {
        [Self::Identity, Self::Via, Self::Mtu, Self::Priority]
            .into_iter()
            .find(|setting| setting.slug() == slug)
    }

    /// The route segment.
    const fn slug(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Via => "via",
            Self::Mtu => "mtu",
            Self::Priority => "priority",
        }
    }

    /// The WAN domain's write, with its audit action id.
    const fn operation(self) -> Operation {
        match self {
            Self::Identity => IDENTITY,
            Self::Via => VIA,
            Self::Mtu => MTU,
            Self::Priority => PRIORITY,
        }
    }

    /// The setting's dialog for `subject` showing `value`; `vias` are the connections a
    /// tunnel may run over.
    fn form(self, subject: Subject<'_>, value: String, vias: &[String]) -> FormDialog {
        let (title, input) = match self {
            Self::Identity => (
                keys::WEB_INTERNET_IDENTITY_TITLE,
                Input::new("value", keys::WEB_INTERNET_IDENTITY, value)
                    .max_chars(IDENTITY_CHARS)
                    .rule(keys::WEB_INTERNET_IDENTITY_ERROR)
                    .help(keys::WEB_INTERNET_IDENTITY_HELP),
            ),
            Self::Via => (
                keys::WEB_INTERNET_VIA_TITLE,
                Input::new("value", keys::WEB_INTERNET_VIA, value)
                    .select(vias.iter().map(|via| Choice::plain(via)).collect()),
            ),
            Self::Mtu => (
                keys::WEB_INTERNET_MTU_TITLE,
                Input::new("value", keys::WEB_NETWORK_MTU, value)
                    .number(MTU_MIN, MTU_MAX)
                    .rule(keys::WEB_INTERNET_MTU_ERROR),
            ),
            Self::Priority => (
                keys::WEB_INTERNET_PRIORITY_TITLE,
                Input::new("value", keys::WEB_NETWORK_PRIORITY, value)
                    .number(0, PRIORITY_MAX)
                    .rule(keys::WEB_INTERNET_PRIORITY_ERROR)
                    .help(keys::WEB_INTERNET_PRIORITY_HELP),
            ),
        };
        FormDialog::new(
            subject.locale(),
            subject.title(title),
            subject.url(&format!("internet/edit/{}", self.slug()), &[]),
        )
        .with_input(input)
    }

    /// The `typed` value, when valid.
    ///
    /// # Errors
    ///
    /// Returns the message saying what a valid value is.
    fn check(self, typed: &str, vias: &[String]) -> Result<Checked, MessageKey> {
        let value = typed.trim();
        let number = |min, max, rule| {
            value
                .parse::<i64>()
                .ok()
                .filter(|number| (min..=max).contains(number))
                .ok_or(rule)
        };
        match self {
            Self::Identity => ((1..=IDENTITY_CHARS).contains(&value.chars().count())
                && !value.chars().any(char::is_control))
            .then(|| Checked::Identity(value.to_owned()))
            .ok_or(keys::WEB_INTERNET_IDENTITY_ERROR),
            Self::Via => vias
                .iter()
                .any(|via| via == value)
                .then(|| ObjectName::try_from(value.to_owned()).ok())
                .flatten()
                .map(Checked::Via)
                .ok_or(keys::WEB_INTERNET_VIA_ERROR),
            Self::Mtu => number(MTU_MIN, MTU_MAX, keys::WEB_INTERNET_MTU_ERROR).map(Checked::Mtu),
            Self::Priority => {
                number(0, PRIORITY_MAX, keys::WEB_INTERNET_PRIORITY_ERROR).map(Checked::Priority)
            }
        }
    }
}

impl Checked {
    /// The WAN domain's plan setting the value on `name`.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    async fn plan(self, domain: &RouterCtx, name: &ObjectName) -> Result<ChangeOp, DomainError> {
        match self {
            Self::Identity(identity) => wan::plan_identity(domain, name, &identity),
            Self::Via(via) => wan::plan_connect_via(domain, name, &via),
            Self::Mtu(mtu) => wan::plan_mtu(domain, name, mtu),
            Self::Priority(priority) => wan::plan_priority(domain, name, priority).await,
        }
    }
}

/// The connections a tunnel named `name` may run over: the IPoE connections but itself.
fn vias(found: &[Link], name: &ObjectName) -> Vec<String> {
    found
        .iter()
        .filter(|link| link.kind() == Some(Kind::Ipoe) && link.id() != name.as_str())
        .map(|link| link.id().to_owned())
        .collect()
}

/// `GET /ui/r/{router}/internet/edit/{setting}?name=`: the dialog of one setting.
///
/// # Errors
///
/// Answers 404 for a setting the page does not edit or a missing connection name, and
/// what the kit answers when the router or the permission is missing.
pub(crate) async fn field_dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let setting = Setting::from_slug(&slug).ok_or_else(missing)?;
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = setting.operation().open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let found = links(&domain).await.unwrap_or_default();
    let link = found.iter().find(|link| link.id() == name.as_str());
    let current = match setting {
        Setting::Identity => None,
        Setting::Via => link.and_then(Link::via).map(str::to_owned),
        Setting::Mtu => link.and_then(Link::mtu_text),
        Setting::Priority => link
            .and_then(Link::priority)
            .map(|priority| priority.to_string()),
    };
    let subject = Subject::new(&router, &name, action.locale());
    Ok(setting
        .form(subject, current.unwrap_or_default(), &vias(&found, &name))
        .show())
}

/// `POST /ui/r/{router}/internet/edit/{setting}?name=`: checks the value, plans it with
/// the WAN domain and runs it.
///
/// # Errors
///
/// Answers the dialog with its field error (422) when the value is invalid, 404 for a
/// setting the page does not edit or a missing connection name, and what the kit answers
/// when the router or the permission is missing.
pub(crate) async fn field(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let setting = Setting::from_slug(&slug).ok_or_else(missing)?;
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let action = setting.operation().open(&state, &user, &router).await?;
    let subject = Subject::new(&router, &name, action.locale());
    let typed = params.text("value");
    let found = if setting == Setting::Via {
        links(&action.context().await?).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let choices = vias(&found, &name);
    let dialog = setting
        .form(subject, typed.to_owned(), &choices)
        .refusing_at("value");
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    Ok(Submission::new(action, &params, dialog)
        .submit(
            |submitted| {
                setting
                    .check(submitted.text("value"), &choices)
                    .map_err(|rule| Invalid::at("value", rule))
            },
            async |checked, domain| {
                let operation = checked.plan(domain, &name).await?;
                let request = wan::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}
