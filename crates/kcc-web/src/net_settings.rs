//! The settings dialog of the network pages.
//!
//! An object's settings as a list: the label, the value or "Not reported", and Edit, which
//! opens the setting's own dialog, only where the role may change it; then the object's
//! buttons, each posting one change.

use askama::Template;
use axum::response::Response;
use kcc_i18n::keys;

use crate::{
    errors,
    page::{Localize, Shell},
    page_kit::respond,
};

/// One setting of a list.
#[derive(Debug, Clone)]
pub(crate) struct Fact {
    /// Element id of the label.
    id: String,
    /// The localized label.
    label: String,
    /// The value, when reported.
    value: Option<String>,
    /// The dialog that changes it, when the role may.
    edit: Option<String>,
}

impl Fact {
    /// The setting `id` labelled `label` (localized) showing `value`.
    pub(crate) fn new(id: &str, label: String, value: Option<String>) -> Self {
        Self {
            id: id.to_owned(),
            label,
            value,
            edit: None,
        }
    }

    /// Offers Edit opening `edit`, when given.
    pub(crate) fn editable(mut self, edit: Option<String>) -> Self {
        self.edit = edit;
        self
    }

    /// Element id of the label.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// The value, when reported.
    pub(crate) fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// The dialog that changes it.
    pub(crate) fn edit(&self) -> Option<&str> {
        self.edit.as_deref()
    }
}

/// A button of a settings dialog: it posts one change, its answer lands in the page's
/// outcome region.
#[derive(Debug, Clone)]
pub(crate) struct Button {
    /// Where it posts.
    href: String,
    /// The localized label.
    label: String,
}

impl Button {
    /// A button posting to `href`, labelled `label` (localized).
    pub(crate) const fn new(href: String, label: String) -> Self {
        Self { href, label }
    }

    /// Where it posts.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }
}

/// A settings dialog.
#[derive(Template)]
#[template(path = "partials/net_settings.html")]
pub(crate) struct SettingsDialog {
    /// Locale carrier.
    shell: Shell,
    /// The localized title.
    title: String,
    /// The settings.
    facts: Vec<Fact>,
    /// The object's buttons.
    buttons: Vec<Button>,
}

impl Localize for SettingsDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl SettingsDialog {
    /// The dialog titled `title` (localized) listing `facts`.
    pub(crate) const fn new(shell: Shell, title: String, facts: Vec<Fact>) -> Self {
        Self {
            shell,
            title,
            facts,
            buttons: Vec::new(),
        }
    }

    /// Adds `button`.
    pub(crate) fn with_button(mut self, button: Button) -> Self {
        self.buttons.push(button);
        self
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }
}
