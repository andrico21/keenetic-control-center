//! Confirmations: what a submitted form says about its confirmation, whether a request may
//! run, and the one dialog that asks first (`partials/kit_confirm.html`).
//!
//! The dialog's confirm button sends the original request again with `confirm=yes` and,
//! when a name must be typed, the typed name as `confirm_name`, so the server decides every
//! time; nothing is trusted because a dialog was shown. The original form's values travel
//! by `hx-include` from the page, so a typed secret never passes through the dialog.
//!
//! A request's [`Stakes`] give the [`Guard`] a page family puts on it once: the gate checks
//! a submitted [`Confirmation`] against that guard and the [`Prompt`] asks for exactly what
//! it checks, so the two cannot disagree. Pages with their own words build the [`Dialog`]
//! directly: the typed-name delete of an object that is not a router, the configuration
//! page's destructive actions, the wizards' Apply and Roll back, and the removals of the
//! routing, port forwarding and firewall pages.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod confirm_tests;
mod dialog;
mod prompt;
mod stakes;

use askama::Template;
use kcc_catalog::Risk;
use kcc_domain::configuration::MANAGEMENT_SECONDS;
use kcc_i18n::{bundle::MessageKey, keys};
use serde::Deserialize;

use super::{family::Family, request::last};
use crate::page::{Localize as _, Shell};

/// Minutes the fail-safe timer runs while a management change is applied.
pub(crate) const FAIL_SAFE_MINUTES: u64 = MANAGEMENT_SECONDS.div_euclid(60);

/// The confirmation a submitted form carries: `confirm` and `confirm_name`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(from = "Sent")]
pub(crate) struct Confirmation {
    /// Whether the dialog's confirm button sent the form.
    confirmed: bool,
    /// The name typed into the dialog.
    name: Option<String>,
}

/// The dialog's fields as sent, before they are read.
#[derive(Deserialize)]
struct Sent {
    /// `yes` from the dialog's confirm button.
    #[serde(default)]
    confirm: Option<String>,
    /// The name typed into the dialog.
    #[serde(default)]
    confirm_name: Option<String>,
}

impl From<Sent> for Confirmation {
    fn from(sent: Sent) -> Self {
        Self::new(sent.confirm.as_deref(), sent.confirm_name.as_deref())
    }
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

    /// The name typed into the dialog, trimmed.
    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// The answer to a typed-name dialog: the object the dialog asked about, and its name
/// typed back.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TypedNameForm {
    /// The name of the object the dialog asked about.
    object: String,
    /// `yes` from the dialog's confirm button.
    confirm: String,
    /// The name as typed by the user.
    confirm_name: String,
}

impl TypedNameForm {
    /// The name of the object the dialog asked about.
    pub(crate) fn name(&self) -> &str {
        &self.object
    }

    /// Whether the dialog was confirmed with the object's name typed exactly.
    pub(crate) fn confirmed(&self) -> bool {
        let confirmation = Confirmation::new(Some(&self.confirm), Some(&self.confirm_name));
        confirmation.confirmed() && confirmation.name() == Some(self.object.as_str())
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

/// A dialog's words, localized: its title, the explanation and the confirm button.
pub(crate) struct Words {
    /// The title.
    title: String,
    /// The explanation.
    text: String,
    /// The confirm button.
    button: String,
}

/// What the dialog's form sends besides the original request.
pub(crate) enum Ask {
    /// Nothing: the button alone confirms (a removal on the routing, port forwarding and
    /// firewall pages).
    Button,
    /// `confirm=yes`.
    Acknowledge,
    /// `confirm=yes` and the name typed as `confirm_name`.
    Typed(Typed),
}

/// The name field of a dialog that needs a name typed.
pub(crate) struct Typed {
    /// The field's localized label.
    label: String,
    /// Localized instruction under the field, empty when the text already gives it.
    help: String,
    /// Localized mismatch or refusal message, empty when none.
    error: String,
    /// The name of the object the dialog asks about, sent back as `object` for a handler
    /// that has no other way to know it.
    object: Option<String>,
}

/// What the dialog says about saving the request.
pub(crate) enum Saved {
    /// Nothing.
    Unsaid,
    /// The router persists the request at once.
    Persists,
    /// The router persists part of the request at once: the localized explanation naming
    /// the persisted paths.
    Mixed(String),
}

/// The confirmation dialog, shown in the shared `<dialog>`.
#[derive(Template)]
#[template(path = "partials/kit_confirm.html")]
pub(crate) struct Dialog {
    /// Locale carrier.
    shell: Shell,
    /// The words.
    words: Words,
    /// Message key of the explanation, as the stable marker of a kit confirmation.
    text_key: Option<MessageKey>,
    /// What the dialog says about saving.
    saved: Saved,
    /// Lists under the text, such as what a delete removes and what it keeps: each a lead
    /// sentence and the object names it introduces.
    lists: Vec<(String, Vec<String>)>,
    /// Where confirm sends the request.
    resubmit: Resubmit,
    /// What the form sends.
    ask: Ask,
}

localized!(Dialog);

/// A request waiting for its confirmation: the dialog asking for what its guard checks.
pub(crate) struct Prompt {
    /// The page family's words.
    family: Family,
    /// What the dialog asks for and explains, as the gate decided it.
    guard: Guard,
    /// Router profile id, the name to type.
    router: String,
    /// What people read for the router: its display name, else the id.
    name: String,
    /// Whether a typed router name did not match.
    wrong_name: bool,
    /// Whether the router persists the request at once.
    persists: bool,
    /// Persisted leaf paths when the rest still needs a save.
    persisted_paths: Vec<String>,
}

/// What a request puts at stake: its catalog risk and whether it can change how kcc
/// reaches the router, which runs it inside the recovery timer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stakes {
    /// The request's risk.
    risk: Risk,
    /// Whether it can change how kcc reaches the router, so it runs inside the recovery
    /// timer.
    management: bool,
}

/// What confirming a request takes, and what its dialog explains.
///
/// A destructive management change needs the router name typed and runs inside the timer;
/// its one dialog says both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guard {
    /// The confirm button; the dialog describes the change.
    Write,
    /// The confirm button; the dialog explains the recovery timer.
    Management,
    /// The router name typed; the dialog says the change cannot be undone.
    Destructive,
    /// The router name typed; the dialog explains the recovery timer the change runs in.
    DestructiveManagement,
}
