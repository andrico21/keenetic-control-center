//! The pieces of a table row and a panel: cells, state pills and action buttons.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};

use crate::table::rows::SortKey;

/// The look of a state pill: the `data-status` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pill {
    /// Enabled, running.
    On,
    /// Disabled, or not reported.
    Off,
}

/// One table cell.
#[derive(Debug, Clone)]
pub(crate) struct Cell {
    /// The text, or the first line.
    text: String,
    /// Every line, for a cell holding several values.
    lines: Vec<String>,
    /// Whether the value is an identifier or an address (mono face).
    mono: bool,
    /// The pill's `data-status`, for a state.
    status: Option<&'static str>,
    /// Whether the router reported nothing.
    missing: bool,
}

impl Cell {
    /// Plain text.
    pub(crate) const fn text(value: String) -> Self {
        Self {
            text: value,
            lines: Vec::new(),
            mono: false,
            status: None,
            missing: false,
        }
    }

    /// An identifier, an address or a URL.
    pub(crate) fn code(value: String) -> Self {
        Self {
            mono: true,
            ..Self::text(value)
        }
    }

    /// Several identifiers, one per line; none is [`Cell::missing`] with `none`.
    pub(crate) fn codes(locale: Locale, values: Vec<String>, none: MessageKey) -> Self {
        values.first().cloned().map_or_else(
            || Self::missing(locale, none),
            |first| Self {
                text: first,
                lines: values,
                mono: true,
                status: None,
                missing: false,
            },
        )
    }

    /// The same values in the body face, for text rather than identifiers.
    pub(crate) fn plain(self) -> Self {
        Self {
            mono: false,
            ..self
        }
    }

    /// The message `key` in `locale`.
    pub(crate) fn word(locale: Locale, key: MessageKey) -> Self {
        Self::text(tr(locale, key, None))
    }

    /// A state pill reading `key`.
    pub(crate) fn pill(locale: Locale, pill: Pill, key: MessageKey) -> Self {
        let status = match pill {
            Pill::On => "online",
            Pill::Off => "unknown",
        };
        Self {
            status: Some(status),
            ..Self::word(locale, key)
        }
    }

    /// A value the router did not report, reading `key`.
    pub(crate) fn missing(locale: Locale, key: MessageKey) -> Self {
        Self {
            missing: true,
            ..Self::word(locale, key)
        }
    }

    /// The text, or the first line.
    pub(crate) fn shown_text(&self) -> &str {
        &self.text
    }

    /// Every line of a cell holding several values; empty otherwise.
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Whether the value is an identifier or an address, shown in the mono face.
    pub(crate) const fn mono(&self) -> bool {
        self.mono
    }

    /// The pill's `data-status`, for a state.
    pub(crate) const fn status(&self) -> Option<&'static str> {
        self.status
    }

    /// Whether the router reported nothing.
    pub(crate) const fn is_missing(&self) -> bool {
        self.missing
    }

    /// The value this cell sorts by.
    pub(crate) fn key(&self) -> SortKey {
        if self.missing {
            SortKey::Missing
        } else {
            SortKey::text(&self.text)
        }
    }

    /// Every text this cell shows, for the table filter.
    pub(crate) fn shown(&self) -> String {
        if self.lines.is_empty() {
            self.text.clone()
        } else {
            self.lines.join(" ")
        }
    }
}

/// How an action button sends its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// Opens a dialog: `GET` into the shared dialog.
    Open,
    /// Posts hidden fields; the outcome lands in the page's outcome region.
    Post,
    /// Goes to another page.
    Link,
}

/// One action button of a page head, a panel or a table row.
#[derive(Debug, Clone)]
pub(crate) struct Act {
    /// The localized label.
    label: String,
    /// Where the request goes.
    href: String,
    /// The button class: `button--ghost`, `button--primary`, ...
    style: &'static str,
    /// How the request is sent.
    method: Method,
    /// Hidden fields of a post.
    fields: Vec<(&'static str, String)>,
}

impl Act {
    /// A button opening the dialog at `href`.
    pub(crate) fn open(locale: Locale, label: MessageKey, href: String) -> Self {
        Self {
            label: tr(locale, label, None),
            href,
            style: "button--ghost",
            method: Method::Open,
            fields: Vec::new(),
        }
    }

    /// A button posting `fields` to `href`.
    pub(crate) fn post(
        locale: Locale,
        label: MessageKey,
        (href, fields): (String, Vec<(&'static str, String)>),
    ) -> Self {
        Self {
            method: Method::Post,
            fields,
            ..Self::open(locale, label, href)
        }
    }

    /// A link to `href`.
    pub(crate) fn link(locale: Locale, label: MessageKey, href: String) -> Self {
        Self {
            method: Method::Link,
            ..Self::open(locale, label, href)
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

    /// Where the request goes.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// The button class.
    pub(crate) const fn style(&self) -> &'static str {
        self.style
    }

    /// Hidden fields of a post.
    pub(crate) fn fields(&self) -> &[(&'static str, String)] {
        &self.fields
    }

    /// Whether the action posts.
    pub(crate) fn is_post(&self) -> bool {
        self.method == Method::Post
    }

    /// Whether the action is a link.
    pub(crate) fn is_link(&self) -> bool {
        self.method == Method::Link
    }
}
