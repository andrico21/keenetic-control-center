//! The action buttons of a page head, a panel or a table row: a dialog opener, a form, an
//! htmx post, a link or a download, a note in their place, or a menu of further actions.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};

/// What a menu entry does.
#[derive(Debug, Clone)]
enum Entry {
    /// Opens a dialog.
    Open,
    /// Posts, then hides the menu.
    Post,
    /// Hides the menu, then posts: the menu attributes come first.
    Hide,
    /// Goes to another page.
    Link,
    /// Downloads a file.
    Download,
    /// A form posting hidden fields.
    Form(Vec<(&'static str, String)>),
}

/// One entry of an action menu.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct MenuItem {
    /// The localized label.
    label: String,
    /// Where the request goes.
    href: String,
    /// What the entry does.
    entry: Entry,
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
    /// Downloads a file.
    Download,
    /// A form posting hidden fields whose answer replaces nothing on the page.
    Quiet(Vec<(&'static str, String)>),
    /// Says why there is no action.
    Note,
    /// Opens the menu of this class whose element id is the action's `href`.
    Menu(&'static str, Vec<MenuItem>),
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
    /// An entry reading `label` that does `entry` with `href`.
    const fn new(label: String, href: String, entry: Entry) -> Self {
        Self {
            label,
            href,
            entry,
            danger: false,
        }
    }

    /// An entry opening the dialog at `href`.
    pub(crate) const fn open(label: String, href: String) -> Self {
        Self::new(label, href, Entry::Open)
    }

    /// An entry posting to `href`.
    pub(crate) const fn post(label: String, href: String) -> Self {
        Self::new(label, href, Entry::Post)
    }

    /// An entry posting to `href` that names the menu it hides first.
    pub(crate) const fn hides(label: String, href: String) -> Self {
        Self::new(label, href, Entry::Hide)
    }

    /// An entry going to `href`.
    pub(crate) const fn link(label: String, href: String) -> Self {
        Self::new(label, href, Entry::Link)
    }

    /// An entry downloading `href`.
    pub(crate) const fn download(label: String, href: String) -> Self {
        Self::new(label, href, Entry::Download)
    }

    /// An entry whose form posts `fields` to `href`.
    pub(crate) fn form(
        label: String,
        (href, fields): (String, Vec<(&'static str, String)>),
    ) -> Self {
        Self::new(label, href, Entry::Form(fields))
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

    /// Whether the entry posts, then hides the menu.
    pub(crate) const fn is_post(&self) -> bool {
        matches!(self.entry, Entry::Post)
    }

    /// Whether the entry hides the menu, then posts.
    pub(crate) const fn is_hide(&self) -> bool {
        matches!(self.entry, Entry::Hide)
    }

    /// Whether the entry is a link or a download.
    pub(crate) const fn is_link(&self) -> bool {
        matches!(self.entry, Entry::Link | Entry::Download)
    }

    /// Whether the entry downloads a file.
    pub(crate) const fn is_download(&self) -> bool {
        matches!(self.entry, Entry::Download)
    }

    /// The hidden fields of a form entry.
    pub(crate) fn form_fields(&self) -> Option<&[(&'static str, String)]> {
        match &self.entry {
            Entry::Form(fields) => Some(fields),
            Entry::Open | Entry::Post | Entry::Hide | Entry::Link | Entry::Download => None,
        }
    }

    /// Where the entry's line starts in a menu indented by `indent`: a form entry two
    /// columns left of it.
    pub(crate) fn lead<'indent>(&self, indent: &'indent str) -> &'indent str {
        match self.entry {
            Entry::Form(_) => indent.get(2..).unwrap_or(indent),
            Entry::Open | Entry::Post | Entry::Hide | Entry::Link | Entry::Download => indent,
        }
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

    /// A link downloading `href`.
    pub(crate) fn download(locale: Locale, label: MessageKey, href: String) -> Self {
        Self {
            method: Method::Download,
            ..Self::open(locale, label, href)
        }
    }

    /// A button whose form posts `fields` to `href` and swaps nothing.
    pub(crate) fn quiet(
        locale: Locale,
        label: MessageKey,
        (href, fields): (String, Vec<(&'static str, String)>),
    ) -> Self {
        Self {
            method: Method::Quiet(fields),
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
    pub(crate) fn menu(label: String, id: String, items: Vec<MenuItem>) -> Self {
        Self::menu_of(label, (id, "menu lan-menu"), items)
    }

    /// A button reading `label` that opens the menu `id` of class `class` of `items`.
    pub(crate) fn menu_of(
        label: String,
        (id, class): (String, &'static str),
        items: Vec<MenuItem>,
    ) -> Self {
        Self {
            label,
            href: id,
            style: "button--ghost",
            method: Method::Menu(class, items),
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
            Method::Post(fields) | Method::Quiet(fields) => fields,
            Method::Open
            | Method::Send
            | Method::Link
            | Method::Download
            | Method::Note
            | Method::Menu(..) => &[],
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

    /// Whether the action is a form post that swaps nothing.
    pub(crate) const fn is_quiet(&self) -> bool {
        matches!(self.method, Method::Quiet(_))
    }

    /// Whether the action is a link or a download.
    pub(crate) const fn is_link(&self) -> bool {
        matches!(self.method, Method::Link | Method::Download)
    }

    /// Whether the action downloads a file.
    pub(crate) const fn is_download(&self) -> bool {
        matches!(self.method, Method::Download)
    }

    /// Whether the action is a note.
    pub(crate) const fn is_note(&self) -> bool {
        matches!(self.method, Method::Note)
    }

    /// The class and entries of a menu.
    pub(crate) fn menu_items(&self) -> Option<(&'static str, &[MenuItem])> {
        match &self.method {
            Method::Menu(class, items) => Some((class, items)),
            Method::Open
            | Method::Post(_)
            | Method::Quiet(_)
            | Method::Send
            | Method::Link
            | Method::Download
            | Method::Note => None,
        }
    }
}
