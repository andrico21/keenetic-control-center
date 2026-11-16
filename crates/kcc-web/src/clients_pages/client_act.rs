//! What a row action of the clients page does: the action named by the route, the value
//! it posts checked at the boundary, and the clients domain's plan for it.

use kcc_app::workflow::CliChangeResult;
use kcc_domain::{
    ChangeOp, DomainError, Result as DomainResult, RouterCtx,
    clients::{self, Access, Client},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use url::form_urlencoded::byte_serialize;

use crate::page_kit::{
    action::Operation,
    change::Applied,
    form::{self, FormDialog},
};

/// The clients domain's writes the page offers, for the table's actions column.
pub(crate) const NAMES: [&str; 7] = [
    "register", "access", "policy", "schedule", "priority", "wake", "remove",
];

/// Longest name, policy or schedule accepted, in characters.
const NAME_CHARS: usize = 64;

/// A row action, named by its route segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Act {
    /// Register or rename.
    Name,
    /// Block or permit.
    Access,
    /// Set the connection policy.
    Policy,
    /// Set the schedule.
    Schedule,
    /// Set the priority.
    Priority,
    /// Send a Wake-on-LAN packet.
    Wake,
    /// Forget a registered client.
    Remove,
}

/// What an action does, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Input {
    /// Register or rename to this name.
    Name(String),
    /// Permit or deny.
    Access(Access),
    /// Use this connection policy.
    Policy(String),
    /// Use this schedule.
    Schedule(String),
    /// Use this priority, 1 to 7.
    Priority(u8),
    /// Wake the client.
    Wake,
    /// Forget the client.
    Remove,
}

impl Act {
    /// The action named by the route segment `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "name" => Some(Self::Name),
            "access" => Some(Self::Access),
            "policy" => Some(Self::Policy),
            "schedule" => Some(Self::Schedule),
            "priority" => Some(Self::Priority),
            "wake" => Some(Self::Wake),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }

    /// The clients domain's write, with its audit action id.
    pub(crate) const fn operation(self) -> Operation {
        let (name, audit) = match self {
            Self::Name => ("register", "web.clients_register"),
            Self::Access => ("access", "web.clients_access"),
            Self::Policy => ("policy", "web.clients_policy"),
            Self::Schedule => ("schedule", "web.clients_schedule"),
            Self::Priority => ("priority", "web.clients_priority"),
            Self::Wake => ("wake", "web.clients_wake"),
            Self::Remove => ("remove", "web.clients_remove"),
        };
        Operation::write(&clients::DESCRIPTOR, name, audit)
    }

    /// The one-field dialog of an action that asks for a value.
    pub(crate) fn dialog(self, router: &str, mac: &str, locale: Locale) -> Option<FormDialog> {
        let (slug, title, label, help) = match self {
            Self::Name => (
                "name",
                keys::WEB_CLIENTS_NAME_TITLE,
                keys::WEB_CLIENTS_NAME_LABEL,
                keys::WEB_CLIENTS_NAME_HELP,
            ),
            Self::Policy => (
                "policy",
                keys::WEB_CLIENTS_POLICY_TITLE,
                keys::WEB_CLIENTS_POLICY_LABEL,
                keys::WEB_CLIENTS_POLICY_HELP,
            ),
            Self::Schedule => (
                "schedule",
                keys::WEB_CLIENTS_SCHEDULE_TITLE,
                keys::WEB_CLIENTS_SCHEDULE_LABEL,
                keys::WEB_CLIENTS_SCHEDULE_HELP,
            ),
            Self::Priority => (
                "priority",
                keys::WEB_CLIENTS_PRIORITY_TITLE,
                keys::WEB_CLIENTS_PRIORITY_LABEL,
                keys::WEB_CLIENTS_PRIORITY_HELP,
            ),
            Self::Access | Self::Wake | Self::Remove => return None,
        };
        let query: String = byte_serialize(mac.as_bytes()).collect();
        let post_to = format!("/ui/r/{router}/clients/{slug}?mac={query}");
        Some(
            FormDialog::new(locale, title, post_to).with_input(
                form::Input::field("value", label, String::new())
                    .id("kit-field")
                    .help(help),
            ),
        )
    }

    /// The posted `value` checked for this action; else why it is refused. `None` for a
    /// value no page control sends.
    pub(crate) fn check(self, value: &str) -> Option<Result<Input, MessageKey>> {
        let text = value.trim();
        Some(match self {
            Self::Name => is_name(text)
                .then(|| Input::Name(text.to_owned()))
                .ok_or(keys::WEB_CLIENTS_NAME_ERROR),
            Self::Policy => is_name(text)
                .then(|| Input::Policy(text.to_owned()))
                .ok_or(keys::WEB_CLIENTS_OBJECT_ERROR),
            Self::Schedule => is_name(text)
                .then(|| Input::Schedule(text.to_owned()))
                .ok_or(keys::WEB_CLIENTS_OBJECT_ERROR),
            Self::Priority => text
                .parse::<u8>()
                .ok()
                .filter(|priority| (1..=7).contains(priority))
                .map(Input::Priority)
                .ok_or(keys::WEB_CLIENTS_PRIORITY_ERROR),
            Self::Access => match text {
                "deny" => Ok(Input::Access(Access::Deny)),
                "permit" => Ok(Input::Access(Access::Permit)),
                _ => return None,
            },
            Self::Wake => Ok(Input::Wake),
            Self::Remove => Ok(Input::Remove),
        })
    }

    /// The current value of the dialog's field for `client`.
    pub(crate) fn current(self, client: &Client) -> String {
        match self {
            Self::Name => client.name.clone(),
            Self::Policy => client.policy.clone(),
            Self::Schedule => client.schedule.clone(),
            Self::Priority => client.priority.map(|priority| priority.to_string()),
            Self::Access | Self::Wake | Self::Remove => None,
        }
        .unwrap_or_default()
    }
}

impl Input {
    /// The clients domain's plan for `client` on the router of `domain`.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    pub(crate) fn plan(&self, domain: &RouterCtx, client: &Client) -> DomainResult<ChangeOp> {
        let mac = client.mac.as_deref().unwrap_or_default();
        let name = clients::registration_name(client);
        match self {
            Self::Name(wanted) => clients::plan_register(
                domain,
                mac.parse().map_err(|_error| DomainError::InvalidResponse)?,
                wanted,
            ),
            Self::Access(access) => clients::plan_access(domain, client, &name, *access),
            Self::Policy(policy) => clients::plan_policy(domain, client, &name, policy),
            Self::Schedule(schedule) => clients::plan_schedule(domain, client, &name, schedule),
            Self::Priority(priority) => clients::plan_priority(domain, client, &name, *priority),
            Self::Wake => clients::plan_wake(domain, mac),
            Self::Remove => clients::plan_remove(domain, mac),
        }
    }

    /// What the router's answer means for the page: a wake changes no setting.
    pub(crate) fn applied(&self, result: CliChangeResult) -> Applied {
        match self {
            Self::Wake => Applied::Done { unsaved: false },
            Self::Name(_)
            | Self::Access(_)
            | Self::Policy(_)
            | Self::Schedule(_)
            | Self::Priority(_)
            | Self::Remove => Applied::Cli {
                unsaved: result.unsaved,
                responses: result.responses,
            },
        }
    }
}

/// Whether `value` is a name, policy or schedule the page sends: 1 to 64 letters, digits,
/// hyphens, underscores or dots, so it stays one word of the router's command line.
fn is_name(value: &str) -> bool {
    (1..=NAME_CHARS).contains(&value.chars().count())
        && value
            .chars()
            .all(|letter| letter.is_alphanumeric() || matches!(letter, '-' | '_' | '.'))
}
