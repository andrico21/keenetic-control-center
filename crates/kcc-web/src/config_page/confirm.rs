//! The confirmation of this page's destructive actions: rolling the fail-safe timer back,
//! deleting a backup and restoring one as the router's saved configuration.
//!
//! Each needs the router name typed, exactly as the kit's destructive confirmation does
//! (`Family::Changes`), with a dialog that says what this action does. The server decides
//! on every request; showing the dialog trusts nothing.

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_catalog::Risk;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    errors,
    page::{Localize, Shell},
    page_kit::{
        confirm::{Confirmation, Gate},
        context::fragment_shell,
        family::Family,
        respond,
    },
};

/// The dialog asking for the router name before a destructive action.
#[derive(Template)]
#[template(path = "partials/config_confirm.html")]
pub(crate) struct ConfirmDialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// What the action does, localized.
    text: String,
    /// Where confirming sends the action again, its object in the query.
    action: String,
    /// The mismatch error, empty when none.
    name_error: String,
    /// The confirming button.
    button: MessageKey,
}

impl Localize for ConfirmDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The words of one confirmation: title, text and button.
pub(crate) type Words = (MessageKey, MessageKey, MessageKey);

/// Whether `pairs` confirm a destructive action on `router`: the dialog's button and the
/// router name typed exactly.
pub(crate) fn gate(pairs: &[(String, String)], router: &str) -> Gate {
    Family::Changes.gate(Risk::Destructive, &Confirmation::from_pairs(pairs), router)
}

impl ConfirmDialog {
    /// The dialog in `locale` posting to `action`, in `words` whose variables come from
    /// `args`.
    pub(crate) fn new(
        locale: Locale,
        action: String,
        (words, args): (Words, &FluentArgs<'_>),
    ) -> Self {
        let (title, text, button) = words;
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, title, Some(args)),
            text: tr(locale, text, Some(args)),
            action,
            name_error: String::new(),
            button,
        }
    }

    /// Shows the dialog, with the mismatch error when the typed name of `router` was
    /// wrong.
    pub(crate) fn ask(mut self, wrong_name: bool, router: &str) -> Response {
        if wrong_name {
            let mut args = FluentArgs::new();
            args.set("router", router.to_owned());
            self.name_error = tr(
                self.shell.locale(),
                keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
                Some(&args),
            );
        }
        respond::in_dialog(errors::render(&self))
    }
}
