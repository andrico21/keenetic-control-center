//! The wizard's confirmation dialog: Apply asks before it starts, Roll back asks for
//! the router name. Confirming sends the request again with `confirm=yes`.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{keys, locale::Locale};
use serde::Deserialize;

use crate::{
    errors,
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, respond},
};

/// The confirmation sent back.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Confirm {
    /// `yes` from the dialog's confirm button.
    #[serde(default)]
    confirm: Option<String>,
    /// The router name typed into the dialog.
    #[serde(default)]
    confirm_name: Option<String>,
}

impl Confirm {
    /// Whether the dialog's confirm button sent the form.
    pub(crate) fn confirmed(&self) -> bool {
        self.confirm.as_deref() == Some("yes")
    }

    /// The typed router name, trimmed.
    pub(crate) fn name(&self) -> Option<&str> {
        self.confirm_name.as_deref().map(str::trim)
    }
}

/// The dialog's words: its title, the explanation and the confirm button.
pub(crate) struct Words {
    /// The title.
    title: String,
    /// The explanation.
    text: String,
    /// The confirm button.
    confirm: String,
}

impl Words {
    /// The words `title`, `text` and `confirm`.
    pub(crate) const fn new(title: String, text: String, confirm: String) -> Self {
        Self {
            title,
            text,
            confirm,
        }
    }
}

/// The wizard's confirmation dialog.
#[derive(Template)]
#[template(path = "partials/migrate_confirm.html")]
pub(crate) struct Dialog {
    /// Locale carrier.
    shell: Shell,
    /// The words.
    words: Words,
    /// Where confirm sends the request.
    action: String,
    /// Whether the router name must be typed.
    needs_name: bool,
    /// The typed name's error.
    name_error: String,
}

impl Localize for Dialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Dialog {
    /// A dialog with `words`, confirming to `action`.
    pub(crate) const fn new(locale: Locale, words: Words, action: String) -> Self {
        Self {
            shell: fragment_shell(locale),
            words,
            action,
            needs_name: false,
            name_error: String::new(),
        }
    }

    /// The dialog asking for the router name, with `error` when one was typed wrong.
    pub(crate) fn with_name(self, error: String) -> Self {
        Self {
            needs_name: true,
            name_error: error,
            ..self
        }
    }

    /// The dialog, in the shared `<dialog>`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }
}

/// `panel` as the step's answer to a confirmed request that failed (422): shown in the
/// step, whatever the request targeted, with the dialog closed.
pub(crate) fn refused<T>(panel: &T) -> Response
where
    T: Template + Localize,
{
    respond::close_dialog(respond::retarget(
        respond::unprocessable(panel),
        "#wizard-step",
    ))
}
