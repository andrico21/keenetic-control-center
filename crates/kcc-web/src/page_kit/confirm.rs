//! Confirmations: what a submitted form says about its confirmation, whether a request may
//! run, and the dialog that asks first.
//!
//! The dialog's confirm button sends the original request again with `confirm=yes` (and
//! the typed router name for destructive changes), so the server decides every time;
//! nothing is trusted because a dialog was shown. The original form's values travel by
//! `hx-include` from the page, so a typed secret never passes through the dialog.

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_domain::configuration::MANAGEMENT_SECONDS;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{context::fragment_shell, family::Family, respond, stakes::Guard};
use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::request::last,
};

/// Minutes the fail-safe timer runs while a management change is applied.
pub(crate) const FAIL_SAFE_MINUTES: u64 = MANAGEMENT_SECONDS.div_euclid(60);

/// The confirmation a submitted form carries.
#[derive(Debug, Clone, Default)]
pub(crate) struct Confirmation {
    /// Whether the dialog's confirm button sent the form.
    confirmed: bool,
    /// The router name typed into the dialog.
    name: Option<String>,
}

impl Confirmation {
    /// Reads `confirm` and `confirm_name` from form pairs; the last value of each counts.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        Self::new(last(pairs, "confirm"), last(pairs, "confirm_name"))
    }

    /// A confirmation from the dialog fields.
    pub(crate) fn new(confirm: Option<&str>, name: Option<&str>) -> Self {
        Self {
            confirmed: confirm == Some("yes"),
            name: name.map(|typed| typed.trim().to_owned()),
        }
    }

    /// Whether the dialog's confirm button sent the form.
    pub(crate) const fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// The router name typed into the dialog, trimmed.
    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// Whether a request may run now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Confirmed as its risk requires, or nothing to confirm.
    Run,
    /// The dialog must ask first; `wrong_name` when a typed name did not match.
    Ask {
        /// Whether the typed router name was wrong.
        wrong_name: bool,
    },
}

/// Where the dialog's confirm button sends the request again.
#[derive(Debug, Clone)]
pub(crate) struct Resubmit {
    /// Endpoint of the original request.
    action: String,
    /// Selector of the region the answer replaces.
    target: &'static str,
    /// Selector of the original form, whose values are sent along from the page.
    include: Option<&'static str>,
}

impl Resubmit {
    /// Sends the confirmation to `action` and shows the answer in `target`.
    pub(crate) const fn new(action: String, target: &'static str) -> Self {
        Self {
            action,
            target,
            include: None,
        }
    }

    /// Sends the current values of the page's form `selector` along.
    pub(crate) const fn with_include(mut self, selector: &'static str) -> Self {
        self.include = Some(selector);
        self
    }
}

/// The confirmation dialog.
#[derive(Template)]
#[template(path = "partials/kit_confirm.html")]
struct Dialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// Localized explanation.
    text: String,
    /// Whether the router name must be typed.
    needs_name: bool,
    /// Localized instruction under the name field, empty when the text already gives it.
    name_help: String,
    /// Localized mismatch error, empty when none.
    name_error: String,
    /// Where confirm sends the request.
    resubmit: Resubmit,
    /// Whether the change is destructive (the confirm button's style).
    destructive: bool,
    /// The confirm button.
    confirm: MessageKey,
    /// Whether the router persists the request at once.
    persists: bool,
    /// Persisted leaf paths when the rest still needs a save.
    persisted_paths: Vec<String>,
    /// Localized mixed-persistence explanation.
    mixed_persistence: String,
    /// Message selected for the pre-run notice and its stable HTML marker.
    mixed_key: MessageKey,
    /// Message selected for the confirmation paragraph.
    text_key: MessageKey,
}

localized!(Dialog);

/// A request waiting for its confirmation: the dialog asking for what its guard checks.
pub(crate) struct Prompt {
    /// The page family's words.
    family: Family,
    /// What the dialog asks for and explains, as the gate decided it.
    guard: Guard,
    /// Router profile id.
    router: String,
    /// Whether a typed router name did not match.
    wrong_name: bool,
    /// Whether the router persists the request at once.
    persists: bool,
    /// Persisted leaf paths when the rest still needs a save.
    persisted_paths: Vec<String>,
}

impl Prompt {
    /// Asks on `router` for the confirmation `guard` checks, in `family`'s words; only the
    /// gate's own decision makes one (`Family::ask`).
    pub(super) fn new(family: Family, guard: Guard, router: &str) -> Self {
        Self {
            family,
            guard,
            router: router.to_owned(),
            wrong_name: false,
            persists: false,
            persisted_paths: Vec::new(),
        }
    }

    /// Reports that the typed router name did not match.
    pub(super) const fn with_wrong_name(mut self, wrong_name: bool) -> Self {
        self.wrong_name = wrong_name;
        self
    }

    /// Labels a request the router persists at once (no save, no fail-safe rollback).
    pub(crate) const fn with_persists(mut self, persists: bool) -> Self {
        self.persists = persists;
        self
    }

    /// Labels persisted leaf paths when the rest of the request still needs a save.
    pub(crate) fn with_persisted_paths(mut self, persisted_paths: Vec<String>) -> Self {
        self.persisted_paths = persisted_paths;
        self
    }

    /// The dialog, shown in the shared `<dialog>`; confirming sends `resubmit`.
    pub(crate) fn render(self, resubmit: Resubmit, locale: Locale) -> Response {
        let mut args = FluentArgs::new();
        args.set("router", self.router.clone());
        args.set("name", self.router.clone());
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        let (title, unsaved_text) = self.family.dialog(self.guard);
        // The router saves such a change itself, so the dialog does not call it unsaved.
        let text = if self.persists && self.guard == Guard::Write {
            keys::WEB_EXPLORER_CONFIRM_PERSIST_TEXT
        } else if !self.persisted_paths.is_empty() && self.guard == Guard::Write {
            keys::WEB_EXPLORER_CONFIRM_MIXED_TEXT
        } else {
            unsaved_text
        };
        let needs_name = self.guard.needs_name();
        // The timer's text does not ask for the name, so the field says what to type.
        let name_help = if self.guard == Guard::DestructiveManagement {
            tr(locale, keys::WEB_ADMIN_CONFIRM_HELP, Some(&args))
        } else {
            String::new()
        };
        let mixed_key = keys::WEB_EXPLORER_MIXED_PERSISTENCE_BEFORE;
        let mixed_persistence = if self.persisted_paths.is_empty() {
            String::new()
        } else {
            let mut mixed_args = FluentArgs::new();
            mixed_args.set("paths", self.persisted_paths.join(", "));
            tr(locale, mixed_key, Some(&mixed_args))
        };
        let dialog = Dialog {
            shell: fragment_shell(locale),
            title: tr(locale, title, Some(&args)),
            text: tr(locale, text, Some(&args)),
            needs_name,
            name_help,
            name_error: if self.wrong_name {
                tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
            } else {
                String::new()
            },
            resubmit,
            destructive: needs_name,
            confirm: self.family.confirm(),
            persists: self.persists,
            persisted_paths: self.persisted_paths,
            mixed_persistence,
            mixed_key,
            text_key: text,
        };
        respond::in_dialog(errors::render(&dialog))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use axum::body::to_bytes;
    use fluent_bundle::FluentArgs;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};

    use super::{FAIL_SAFE_MINUTES, Prompt, Resubmit};
    use crate::page_kit::{family::Family, stakes::Guard};

    /// Mixed persistence never replaces the management risk warning.
    // cancel-safe: only renders and reads an in-memory response body.
    #[tokio::test]
    async fn mixed_management_keeps_management_paragraph() -> Result<(), Box<dyn Error>> {
        let response = Prompt::new(Family::Commands, Guard::Management, "home")
            .with_persisted_paths(vec!["system country".to_owned()])
            .render(
                Resubmit::new("/ui/r/home/console/rci/send".to_owned(), "#rci-result"),
                Locale::En,
            );
        let body = to_bytes(response.into_body(), 0x0001_0000).await?;
        let page = String::from_utf8(body.to_vec())?;
        assert!(page.contains("data-message-key=\"web-explorer-confirm-management-text\""));
        assert!(!page.contains("data-message-key=\"web-explorer-confirm-mixed-text\""));
        Ok(())
    }

    /// The prompt for `guard` on the router `home`, as served.
    async fn prompt(guard: Guard) -> Result<(Option<String>, String), Box<dyn Error>> {
        let resubmit = Resubmit::new("/ui/r/home/system/general/http".to_owned(), "#page-outcome");
        let response = Prompt::new(Family::Changes, guard, "home").render(resubmit, Locale::En);
        let target = response
            .headers()
            .get("hx-retarget")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = to_bytes(response.into_body(), 0x0001_0000).await?;
        Ok((target, String::from_utf8(body.to_vec())?))
    }

    #[tokio::test]
    async fn management_explains_the_timer_and_destructive_asks_for_the_name()
    -> Result<(), Box<dyn Error>> {
        let mut args = FluentArgs::new();
        args.set("router", "home");
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        let (target, management) = prompt(Guard::Management).await?;
        assert_eq!(target.as_deref(), Some("#dialog-content"), "in the dialog");
        let text = tr(
            Locale::En,
            keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT,
            Some(&args),
        )
        .replace('\'', "&#39;");
        assert!(
            management.contains(&text),
            "the fail-safe timer: {management}"
        );
        assert!(
            management
                .contains("hx-post=\"/ui/r/home/system/general/http\" hx-target=\"#page-outcome\""),
            "confirming sends the request again"
        );
        assert!(
            management.contains("<input type=\"hidden\" name=\"confirm\" value=\"yes\">"),
            "with the confirmation"
        );
        assert!(!management.contains("confirm_name"), "no name to type");
        assert!(
            management.contains("button--primary"),
            "not a danger button"
        );
        let (_, destructive) = prompt(Guard::Destructive).await?;
        assert!(
            destructive.contains("name=\"confirm_name\""),
            "the router name"
        );
        assert!(destructive.contains("button--danger"), "a danger button");
        Ok(())
    }
}
