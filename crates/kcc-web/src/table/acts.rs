//! The action buttons of a page head, a panel or a table row: a dialog opener, a form, an
//! htmx post, a link, a note in their place, or a menu of further actions.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};

/// One entry of an action menu.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct MenuItem {
    /// The localized label.
    label: String,
    /// Where the request goes.
    href: String,
    /// Whether the entry posts (and hides the menu) instead of opening a dialog.
    post: bool,
    /// Whether the entry removes something.
    danger: bool,
}

/// How an action sends its request.
#[derive(Debug, Clone)]
enum Method {
    /// Opens a dialog: `GET` into the shared dialog.
    Open,
    /// A form posting hidden fields; the outcome lands in the page's outcome region.
    Post(Vec<(&'static str, String)>),
    /// An htmx post without a form; the outcome lands in the page's outcome region.
    Send,
    /// Goes to another page.
    Link,
    /// Says why there is no action.
    Note,
    /// Opens the menu whose element id is the action's `href`.
    Menu(Vec<MenuItem>),
}

/// One action button.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Act {
    /// The localized label.
    label: String,
    /// Where the request goes; a menu's element id.
    href: String,
    /// The button class: `button--ghost`, `button--primary`, ...
    style: &'static str,
    /// How the request is sent.
    method: Method,
}

impl MenuItem {
    /// An entry opening the dialog at `href`.
    pub(crate) const fn open(label: String, href: String) -> Self {
        Self {
            label,
            href,
            post: false,
            danger: false,
        }
    }

    /// An entry posting to `href`.
    pub(crate) const fn post(label: String, href: String) -> Self {
        Self {
            label,
            href,
            post: true,
            danger: false,
        }
    }

    /// An entry that removes something.
    pub(crate) const fn danger(mut self) -> Self {
        self.danger = true;
        self
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Where the request goes.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// Whether the entry posts (and hides the menu) instead of opening a dialog.
    pub(crate) const fn is_post(&self) -> bool {
        self.post
    }

    /// Whether the entry removes something.
    pub(crate) const fn is_danger(&self) -> bool {
        self.danger
    }
}

impl Act {
    /// A button reading `label` opening the dialog at `href`.
    pub(crate) const fn opens(label: String, href: String) -> Self {
        Self {
            label,
            href,
            style: "button--ghost",
            method: Method::Open,
        }
    }

    /// A button opening the dialog at `href`.
    pub(crate) fn open(locale: Locale, label: MessageKey, href: String) -> Self {
        Self::opens(tr(locale, label, None), href)
    }

    /// A button posting `fields` to `href`.
    pub(crate) fn post(
        locale: Locale,
        label: MessageKey,
        (href, fields): (String, Vec<(&'static str, String)>),
    ) -> Self {
        Self {
            method: Method::Post(fields),
            ..Self::open(locale, label, href)
        }
    }

    /// A button reading `label` that posts to `href` without a form.
    pub(crate) const fn sends(label: String, href: String) -> Self {
        Self {
            label,
            href,
            style: "button--ghost",
            method: Method::Send,
        }
    }

    /// A link to `href`.
    pub(crate) fn link(locale: Locale, label: MessageKey, href: String) -> Self {
        Self {
            method: Method::Link,
            ..Self::open(locale, label, href)
        }
    }

    /// A muted note reading `label` in place of an action.
    pub(crate) const fn note(label: String) -> Self {
        Self {
            label,
            href: String::new(),
            style: "button--ghost",
            method: Method::Note,
        }
    }

    /// A button reading `label` that opens the menu `id` of `items`.
    pub(crate) const fn menu(label: String, id: String, items: Vec<MenuItem>) -> Self {
        Self {
            label,
            href: id,
            style: "button--ghost",
            method: Method::Menu(items),
        }
    }

    /// The page's primary action.
    pub(crate) fn primary(self) -> Self {
        Self {
            style: "button--primary",
            ..self
        }
    }

    /// A secondary action beside the primary one.
    pub(crate) fn secondary(self) -> Self {
        Self {
            style: "button--secondary",
            ..self
        }
    }

    /// An action that removes something.
    pub(crate) fn danger(self) -> Self {
        Self {
            style: "button--danger-ghost",
            ..self
        }
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Where the request goes; a menu's element id.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// The button class.
    pub(crate) const fn style(&self) -> &'static str {
        self.style
    }

    /// Hidden fields of a form post; empty otherwise.
    pub(crate) fn fields(&self) -> &[(&'static str, String)] {
        match &self.method {
            Method::Post(fields) => fields,
            Method::Open | Method::Send | Method::Link | Method::Note | Method::Menu(_) => &[],
        }
    }

    /// Whether the action is a form post.
    pub(crate) const fn is_post(&self) -> bool {
        matches!(self.method, Method::Post(_))
    }

    /// Whether the action is an htmx post without a form.
    pub(crate) const fn is_send(&self) -> bool {
        matches!(self.method, Method::Send)
    }

    /// Whether the action is a link.
    pub(crate) const fn is_link(&self) -> bool {
        matches!(self.method, Method::Link)
    }

    /// Whether the action is a note.
    pub(crate) const fn is_note(&self) -> bool {
        matches!(self.method, Method::Note)
    }

    /// The entries of a menu.
    pub(crate) fn menu_items(&self) -> Option<&[MenuItem]> {
        match &self.method {
            Method::Menu(items) => Some(items),
            Method::Open | Method::Post(_) | Method::Send | Method::Link | Method::Note => None,
        }
    }
}
