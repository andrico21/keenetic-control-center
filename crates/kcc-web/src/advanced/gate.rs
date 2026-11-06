//! Who may run a command of a given catalog risk, and the confirmation it needs.
//!
//! A write is confirmed, a management change is confirmed knowing that kcc arms the
//! router's fail-safe timer, and a destructive command needs the router's name typed.

use askama::Template;
use axum::{
    http::{HeaderValue, StatusCode},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::context::fragment_shell;
use crate::{
    errors,
    page::{Localize, Shell},
};

/// Minutes the fail-safe timer runs while a management change is applied.
pub(crate) const FAIL_SAFE_MINUTES: u64 = 5;

/// [`FAIL_SAFE_MINUTES`] in seconds, as the router's timer takes it.
pub(crate) const FAIL_SAFE_SECONDS: u64 = FAIL_SAFE_MINUTES.saturating_mul(60);

/// The permissions a command of `risk` needs on its router.
pub(crate) const fn permissions(risk: Risk) -> &'static [Permission] {
    match risk {
        Risk::Read => &[Permission::Read],
        Risk::Write => &[Permission::RawRci],
        Risk::Management | Risk::Destructive | _ => &[Permission::RawRci, Permission::Destructive],
    }
}

/// The confirmation a submitted form carries.
#[derive(Debug, Clone, Default)]
pub(crate) struct Confirmation {
    /// Whether the dialog's confirm button sent the form.
    confirmed: bool,
    /// The router name typed into the dialog.
    name: Option<String>,
}

impl Confirmation {
    /// Reads `confirm` and `confirm_name` from form pairs.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let value = |wanted: &str| {
            pairs
                .iter()
                .rev()
                .find(|(name, _)| name == wanted)
                .map(|(_, value)| value.as_str())
        };
        Self::new(value("confirm"), value("confirm_name"))
    }

    /// A confirmation from the dialog fields.
    pub(crate) fn new(confirm: Option<&str>, name: Option<&str>) -> Self {
        Self {
            confirmed: confirm == Some("yes"),
            name: name.map(|typed| typed.trim().to_owned()),
        }
    }
}

/// Whether a request may run now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Confirmed as its risk requires, or read-only.
    Run,
    /// The dialog must ask first; `wrong_name` when a typed name did not match.
    Ask {
        /// Whether the typed router name was wrong.
        wrong_name: bool,
    },
}

/// Whether a request of `risk` on `router` with `confirmation` may run now.
pub(crate) fn gate(risk: Risk, confirmation: &Confirmation, router: &str) -> Gate {
    match risk {
        Risk::Read => Gate::Run,
        Risk::Write | Risk::Management => {
            if confirmation.confirmed {
                Gate::Run
            } else {
                Gate::Ask { wrong_name: false }
            }
        }
        Risk::Destructive | _ => match (&confirmation.name, confirmation.confirmed) {
            (Some(name), true) if name == router => Gate::Run,
            (Some(_), true) => Gate::Ask { wrong_name: true },
            (Some(_) | None, _) => Gate::Ask { wrong_name: false },
        },
    }
}

/// Where the dialog's confirm button sends the original form again.
#[derive(Debug, Clone)]
pub(crate) struct Resubmit {
    /// Endpoint of the original request.
    action: String,
    /// Selector of the original form, whose values are sent along.
    include: &'static str,
    /// Selector of the result region.
    target: &'static str,
}

impl Resubmit {
    /// Sends `include` to `action` and shows the result in `target`.
    pub(crate) const fn new(action: String, include: &'static str, target: &'static str) -> Self {
        Self {
            action,
            include,
            target,
        }
    }
}

/// The confirmation dialog.
#[derive(Template)]
#[template(path = "partials/explorer_confirm.html")]
struct Dialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// Localized explanation.
    text: String,
    /// Whether the router name must be typed.
    needs_name: bool,
    /// Localized mismatch error, empty when none.
    name_error: String,
    /// Where confirm sends the form.
    resubmit: Resubmit,
    /// Whether the command is destructive (the confirm button's style).
    destructive: bool,
}

impl Localize for Dialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// A request waiting for its confirmation.
pub(crate) struct Prompt {
    /// Catalog risk of the request.
    risk: Risk,
    /// Router profile id.
    router: String,
    /// Where confirm sends the form again.
    resubmit: Resubmit,
    /// Whether a typed router name did not match.
    wrong_name: bool,
}

impl Prompt {
    /// Asks to confirm a request of `risk` on `router`.
    pub(crate) fn new(risk: Risk, router: &str, resubmit: Resubmit) -> Self {
        Self {
            risk,
            router: router.to_owned(),
            resubmit,
            wrong_name: false,
        }
    }

    /// Reports that the typed router name did not match.
    pub(crate) const fn with_wrong_name(mut self, wrong_name: bool) -> Self {
        self.wrong_name = wrong_name;
        self
    }

    /// The dialog, shown in the shared `<dialog>` through `HX-Retarget`.
    pub(crate) fn render(self, locale: Locale) -> Response {
        let mut args = FluentArgs::new();
        args.set("router", self.router.clone());
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        let (title, text) = match self.risk {
            Risk::Read | Risk::Write => (
                keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_WRITE_TEXT,
            ),
            Risk::Management => (
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TITLE,
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT,
            ),
            Risk::Destructive | _ => (
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT,
            ),
        };
        let destructive = !matches!(self.risk, Risk::Read | Risk::Write | Risk::Management);
        let dialog = Dialog {
            shell: fragment_shell(locale),
            title: tr(locale, title, Some(&args)),
            text: tr(locale, text, Some(&args)),
            needs_name: destructive,
            name_error: if self.wrong_name {
                tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
            } else {
                String::new()
            },
            resubmit: self.resubmit,
            destructive,
        };
        let mut response = errors::render(&dialog);
        if response.status() == StatusCode::OK {
            let headers = response.headers_mut();
            drop(headers.insert("hx-retarget", HeaderValue::from_static("#dialog-content")));
            drop(headers.insert("hx-reswap", HeaderValue::from_static("innerHTML")));
        }
        response
    }
}

/// Shows `response` in `target` instead of the requesting element's own target, such as a
/// console's live check region, which already holds the same kind of finding.
pub(crate) fn retarget(mut response: Response, target: &'static str) -> Response {
    drop(
        response
            .headers_mut()
            .insert("hx-retarget", HeaderValue::from_static(target)),
    );
    response
}

/// Marks `response` to close the shared dialog when it arrives.
pub(crate) fn close_dialog(mut response: Response) -> Response {
    drop(
        response
            .headers_mut()
            .insert("hx-trigger", HeaderValue::from_static("kcc:dialog-close")),
    );
    response
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_catalog::Risk;

    use super::{Confirmation, Gate, gate};

    #[test]
    fn each_risk_needs_its_confirmation() {
        let none = Confirmation::default();
        let confirmed = Confirmation::new(Some("yes"), None);
        let named = Confirmation::new(Some("yes"), Some(" home "));
        let misnamed = Confirmation::new(Some("yes"), Some("Home"));
        assert_eq!(gate(Risk::Read, &none, "home"), Gate::Run, "reads run");
        assert_eq!(
            gate(Risk::Write, &none, "home"),
            Gate::Ask { wrong_name: false },
            "writes ask"
        );
        assert_eq!(
            gate(Risk::Management, &confirmed, "home"),
            Gate::Run,
            "confirmed"
        );
        assert_eq!(
            gate(Risk::Destructive, &confirmed, "home"),
            Gate::Ask { wrong_name: false },
            "destructive needs the name"
        );
        assert_eq!(
            gate(Risk::Destructive, &misnamed, "home"),
            Gate::Ask { wrong_name: true },
            "names are exact"
        );
        assert_eq!(gate(Risk::Destructive, &named, "home"), Gate::Run, "named");
    }
}
