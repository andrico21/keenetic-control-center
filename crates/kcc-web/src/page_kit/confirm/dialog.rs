//! Building and showing the confirmation dialog.

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{Ask, Dialog, Resubmit, Saved, Typed, Words};
use crate::{
    errors,
    page_kit::{context::fragment_shell, respond},
};

impl Words {
    /// The words `title`, `text` and `button`, localized.
    pub(crate) const fn new(title: String, text: String, button: String) -> Self {
        Self {
            title,
            text,
            button,
        }
    }
}

impl Ask {
    /// Whether the confirm button is styled as a danger: a removal, or a name to type.
    pub(super) const fn danger(&self) -> bool {
        match self {
            Self::Button | Self::Typed(_) => true,
            Self::Acknowledge => false,
        }
    }
}

impl Typed {
    /// The router's id to type, under the label "Router ID".
    pub(crate) fn router(locale: Locale) -> Self {
        Self {
            label: tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME, None),
            help: String::new(),
            error: String::new(),
            object: None,
        }
    }

    /// `name` to type, under the label "Name" with the instruction to type it, sent back
    /// as the object the dialog asks about.
    pub(crate) fn object(locale: Locale, name: &str) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        Self {
            label: tr(locale, keys::WEB_ADMIN_CONFIRM_LABEL, None),
            help: tr(locale, keys::WEB_ADMIN_CONFIRM_HELP, Some(&args)),
            error: String::new(),
            object: Some(name.to_owned()),
        }
    }

    /// The field with the instruction `help` under it.
    pub(crate) fn with_help(self, help: String) -> Self {
        Self { help, ..self }
    }

    /// The field with `error` under it; empty for none.
    pub(crate) fn with_error(self, error: String) -> Self {
        Self { error, ..self }
    }
}

impl Dialog {
    /// The dialog in `locale` saying `words`, whose confirm button sends `confirm=yes` by
    /// `resubmit`.
    pub(crate) const fn new(locale: Locale, words: Words, resubmit: Resubmit) -> Self {
        Self {
            shell: fragment_shell(locale),
            words,
            text_key: None,
            saved: Saved::Unsaid,
            lists: Vec::new(),
            resubmit,
            ask: Ask::Acknowledge,
        }
    }

    /// The typed-name confirmation of a destructive change to the object `name`, posting
    /// to `action` and answering in the dialog, with the `(title, text)` messages (the
    /// title may use `$name`) and a Delete button.
    pub(crate) fn typed_name(
        locale: Locale,
        action: String,
        name: &str,
        (title, text): (MessageKey, MessageKey),
    ) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        let words = Words::new(
            tr(locale, title, Some(&args)),
            tr(locale, text, None),
            tr(locale, keys::COMMON_DELETE, None),
        );
        Self::new(locale, words, Resubmit::new(action, "#dialog-content"))
            .asking(Ask::Typed(Typed::object(locale, name)))
    }

    /// The dialog sending `ask` along.
    pub(crate) fn asking(self, ask: Ask) -> Self {
        Self { ask, ..self }
    }

    /// Marks the explanation with its message `key`.
    pub(crate) const fn with_text_key(mut self, key: MessageKey) -> Self {
        self.text_key = Some(key);
        self
    }

    /// The dialog saying `saved` about saving the request.
    pub(crate) fn saying(self, saved: Saved) -> Self {
        Self { saved, ..self }
    }

    /// Labels the confirm button with `button`.
    pub(crate) fn with_button(mut self, button: MessageKey) -> Self {
        self.words.button = tr(self.shell.locale(), button, None);
        self
    }

    /// Lists `items` under the text, introduced by `lead`; no items list nothing.
    pub(crate) fn with_list(mut self, lead: String, items: Vec<String>) -> Self {
        if !items.is_empty() {
            self.lists.push((lead, items));
        }
        self
    }

    /// Shows `error` under the typed name; a dialog that asks for no name has no field to
    /// show it under.
    pub(crate) fn set_error(&mut self, error: String) {
        match &mut self.ask {
            Ask::Typed(typed) => typed.error = error,
            Ask::Button | Ask::Acknowledge => {}
        }
    }

    /// The dialog, in the shared `<dialog>`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }
}
