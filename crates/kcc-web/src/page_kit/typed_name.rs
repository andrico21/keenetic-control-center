//! Typed-name confirmation of a destructive change to an object that is not a router: an
//! account, a role, an API key, later a route or a tunnel.
//!
//! The dialog asks for the object's name and the handler compares it again on submit; a
//! mismatch shows the dialog with its error and changes nothing.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use serde::Deserialize;

use crate::page::{Localize, Shell};

/// A typed-name confirmation: `confirm` must repeat `name`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TypedNameForm {
    /// The object's name.
    name: String,
    /// The name as typed by the user.
    confirm: String,
}

impl TypedNameForm {
    /// The object's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Whether the typed name matches.
    pub(crate) fn confirmed(&self) -> bool {
        self.confirm.trim() == self.name
    }
}

/// The typed-name confirmation dialog.
#[derive(Template)]
#[template(path = "partials/kit_name_confirm.html")]
pub(crate) struct TypedNameDialog {
    /// Locale carrier.
    shell: Shell,
    /// Question naming the object.
    title: String,
    /// What the change does.
    text: MessageKey,
    /// "Type <name> to confirm."
    help: String,
    /// Form target.
    action: String,
    /// The object's name.
    name: String,
    /// Mismatch or refusal message.
    error: String,
    /// The confirming button's label.
    button: MessageKey,
}

impl Localize for TypedNameDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl TypedNameDialog {
    /// The confirmation posting `name` to `action`, with the `(title, text)` messages;
    /// the title may use `$name`.
    pub(crate) fn new(
        shell: Shell,
        action: String,
        name: &str,
        (title, text): (MessageKey, MessageKey),
    ) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        let locale = shell.locale();
        Self {
            title: tr(locale, title, Some(&args)),
            help: tr(locale, keys::WEB_ADMIN_CONFIRM_HELP, Some(&args)),
            shell,
            text,
            action,
            name: name.to_owned(),
            error: String::new(),
            button: keys::COMMON_DELETE,
        }
    }

    /// Labels the confirming button with `button`.
    pub(crate) const fn with_button(mut self, button: MessageKey) -> Self {
        self.button = button;
        self
    }

    /// Shows `error` under the typed name.
    pub(crate) fn set_error(&mut self, error: String) {
        self.error = error;
    }
}
