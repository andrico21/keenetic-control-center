//! The cells of a rendered table: a header or data cell with its attributes, holding text
//! and spans, a list of values, an ordered list of items with buttons, or row actions.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{acts::Act, rows::SortKey};

/// The look of a state pill: the `data-status` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Pill {
    /// Enabled, running.
    On,
    /// Disabled, or not reported.
    Off,
}

/// One inline piece of a cell: bare text, or a span with attributes around the text and
/// an optional inner span (class and text) after it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Piece {
    /// Attributes of the span, in output order; empty for bare text.
    attrs: Vec<(&'static str, String)>,
    /// The text.
    text: String,
    /// An inner span after the text: its class and text.
    inner: Option<(&'static str, String)>,
}

/// The items of an ordered cell list and its classes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Ordered {
    /// Class of the list.
    class: &'static str,
    /// Class of every item.
    item_class: &'static str,
    /// The items: a piece, its actions and what the actions describe themselves by.
    items: Vec<(Piece, Vec<Act>, String)>,
}

/// How a cell lays out its actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Layout {
    /// On the cell's own line.
    Inline,
    /// One per line inside the cell.
    Block,
    /// One per line inside a `div` of this class.
    Wrapped(&'static str),
}

/// What a cell holds.
#[derive(Debug, Clone)]
enum Body {
    /// Text and spans on the cell's line.
    Inline(Vec<Piece>),
    /// Values, one per line (`ul.cell-lines`).
    Lines(Vec<String>),
    /// An ordered list of items with their actions.
    Ordered(Ordered),
    /// Row actions, the layout and what they describe themselves by.
    Acts(Layout, Vec<Act>, String),
}

/// One table cell: a data cell, or the row header.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Cell {
    /// Whether the cell is the row header (`th scope="row"`).
    head: bool,
    /// Attributes, in output order.
    attrs: Vec<(&'static str, String)>,
    /// The content.
    body: Body,
    /// Whether the router reported nothing.
    missing: bool,
}

impl Piece {
    /// Bare text.
    pub(crate) const fn text(text: String) -> Self {
        Self {
            attrs: Vec::new(),
            text,
            inner: None,
        }
    }

    /// `text` in a span of `class`.
    pub(crate) fn span(class: &'static str, text: String) -> Self {
        Self {
            attrs: vec![("class", class.to_owned())],
            ..Self::text(text)
        }
    }

    /// The span with the attribute `name` set to `value` after the others.
    pub(crate) fn attr(mut self, name: &'static str, value: String) -> Self {
        self.attrs.push((name, value));
        self
    }

    /// The span with an inner span of `class` reading `text` after its text.
    pub(crate) fn with_inner(mut self, class: &'static str, text: String) -> Self {
        self.inner = Some((class, text));
        self
    }

    /// Attributes of the span, in output order; empty for bare text.
    pub(crate) fn attrs(&self) -> &[(&'static str, String)] {
        &self.attrs
    }

    /// The text.
    pub(crate) fn content(&self) -> &str {
        &self.text
    }

    /// The inner span after the text: its class and text.
    pub(crate) const fn inner(&self) -> Option<&(&'static str, String)> {
        self.inner.as_ref()
    }
}

impl Ordered {
    /// A list of class `class` whose items have the class `item_class`.
    pub(crate) const fn new(
        (class, item_class): (&'static str, &'static str),
        items: Vec<(Piece, Vec<Act>, String)>,
    ) -> Self {
        Self {
            class,
            item_class,
            items,
        }
    }

    /// Class of the list.
    pub(crate) const fn class(&self) -> &'static str {
        self.class
    }

    /// Class of every item.
    pub(crate) const fn item_class(&self) -> &'static str {
        self.item_class
    }

    /// The items: a piece, its actions and what the actions describe themselves by.
    pub(crate) fn items(&self) -> &[(Piece, Vec<Act>, String)] {
        &self.items
    }
}

impl Cell {
    /// A cell of `pieces`.
    pub(crate) const fn of(pieces: Vec<Piece>) -> Self {
        Self {
            head: false,
            attrs: Vec::new(),
            body: Body::Inline(pieces),
            missing: false,
        }
    }

    /// Plain text.
    pub(crate) fn text(value: String) -> Self {
        Self::of(vec![Piece::text(value)])
    }

    /// The text of `value`, or an empty cell.
    pub(crate) fn optional(value: Option<String>) -> Self {
        Self::of(value.map(Piece::text).into_iter().collect())
    }

    /// An identifier, an address or a URL.
    pub(crate) fn code(value: String) -> Self {
        Self::text(value).class("mono")
    }

    /// Several identifiers, one per line; none is [`Cell::missing`] with `none`.
    pub(crate) fn codes(locale: Locale, values: Vec<String>, none: MessageKey) -> Self {
        if values.is_empty() {
            return Self::missing(locale, none);
        }
        Self {
            body: Body::Lines(values),
            ..Self::of(Vec::new())
        }
        .class("mono")
    }

    /// The same values in the body face, for text rather than identifiers.
    pub(crate) fn plain(mut self) -> Self {
        self.attrs
            .retain(|(name, value)| *name != "class" || value != "mono");
        self
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
        Self::of(vec![
            Piece::span("status", tr(locale, key, None)).attr("data-status", status.to_owned()),
        ])
    }

    /// The text of `value`, or "not reported" in `locale`.
    pub(crate) fn reported(locale: Locale, value: Option<String>) -> Self {
        value.map_or_else(
            || Self::missing(locale, keys::WEB_KIT_NOT_REPORTED),
            Self::text,
        )
    }

    /// A value the router did not report, reading `key`.
    pub(crate) fn missing(locale: Locale, key: MessageKey) -> Self {
        Self {
            missing: true,
            ..Self::of(vec![Piece::span("muted", tr(locale, key, None))])
        }
    }

    /// An ordered list of items.
    pub(crate) fn ordered(list: Ordered) -> Self {
        Self {
            body: Body::Ordered(list),
            ..Self::of(Vec::new())
        }
    }

    /// Row actions laid out as `layout`, described by the element ids `described_by`.
    pub(crate) fn acts(layout: Layout, acts: Vec<Act>, described_by: String) -> Self {
        Self {
            body: Body::Acts(layout, acts, described_by),
            ..Self::of(Vec::new())
        }
    }

    /// The cell with the attribute `name` set to `value` after the others.
    pub(crate) fn attr(mut self, name: &'static str, value: String) -> Self {
        self.attrs.push((name, value));
        self
    }

    /// The cell with the class `class`.
    pub(crate) fn class(self, class: &'static str) -> Self {
        self.attr("class", class.to_owned())
    }

    /// The cell as the row header.
    pub(crate) const fn head(mut self) -> Self {
        self.head = true;
        self
    }

    /// The cell as the row header with the element id `id` first, showing its text only.
    pub(crate) fn head_with_id(self, id: String) -> Self {
        let text = self.shown_text();
        let mut attrs = vec![("id", id)];
        attrs.extend(self.attrs);
        Self {
            head: true,
            attrs,
            body: Body::Inline(vec![Piece::text(text)]),
            missing: self.missing,
        }
    }

    /// Whether the cell is the row header.
    pub(crate) const fn is_head(&self) -> bool {
        self.head
    }

    /// Attributes, in output order.
    pub(crate) fn attrs(&self) -> &[(&'static str, String)] {
        &self.attrs
    }

    /// The pieces of a cell of text and spans; empty otherwise.
    pub(crate) fn pieces(&self) -> &[Piece] {
        match &self.body {
            Body::Inline(pieces) => pieces,
            Body::Lines(_) | Body::Ordered(_) | Body::Acts(..) => &[],
        }
    }

    /// The values of a cell holding several, one per line; empty otherwise.
    pub(crate) fn lines(&self) -> &[String] {
        match &self.body {
            Body::Lines(lines) => lines,
            Body::Inline(_) | Body::Ordered(_) | Body::Acts(..) => &[],
        }
    }

    /// The ordered list of a list cell.
    pub(crate) const fn ordered_list(&self) -> Option<&Ordered> {
        match &self.body {
            Body::Ordered(list) => Some(list),
            Body::Inline(_) | Body::Lines(_) | Body::Acts(..) => None,
        }
    }

    /// The actions of an action cell: layout, actions and the ids they are described by.
    pub(crate) fn actions(&self) -> Option<(Layout, &[Act], &str)> {
        match &self.body {
            Body::Acts(layout, acts, described_by) => Some((*layout, acts, described_by)),
            Body::Inline(_) | Body::Lines(_) | Body::Ordered(_) => None,
        }
    }

    /// The text of the cell: its pieces joined, or its first value.
    pub(crate) fn shown_text(&self) -> String {
        match &self.body {
            Body::Lines(lines) => lines.first().cloned().unwrap_or_default(),
            Body::Inline(pieces) => pieces.iter().map(|piece| piece.text.as_str()).collect(),
            Body::Ordered(_) | Body::Acts(..) => String::new(),
        }
    }

    /// The pill's `data-status`, for a state.
    pub(crate) fn status(&self) -> Option<&str> {
        self.pieces().first().and_then(|piece| {
            piece
                .attrs
                .iter()
                .find_map(|(name, value)| (*name == "data-status").then_some(value.as_str()))
        })
    }

    /// The value this cell sorts by.
    pub(crate) fn key(&self) -> SortKey {
        if self.missing {
            SortKey::Missing
        } else {
            SortKey::text(&self.shown_text())
        }
    }

    /// Every text this cell shows, for the table filter.
    pub(crate) fn shown(&self) -> String {
        match &self.body {
            Body::Lines(lines) => lines.join(" "),
            Body::Inline(_) | Body::Ordered(_) | Body::Acts(..) => self.shown_text(),
        }
    }
}
