//! The inline content of a table cell.
//!
//! A piece is bare text, or an element (`span`, `a`, `time`, `code`, ...) with its
//! attributes around its text and the elements after it; a cell may also put its content
//! one element per line.

/// One inline piece of a cell: bare text, or an element with attributes around its text,
/// followed by child elements.
#[derive(Debug, Clone)]
pub(crate) struct Piece {
    /// The element; none for bare text.
    tag: Option<&'static str>,
    /// Attributes of the element, in output order.
    attrs: Vec<(&'static str, String)>,
    /// A valueless attribute after the others, such as `data-kcc-time`.
    flag: Option<&'static str>,
    /// The text.
    text: String,
    /// Elements after the text, each shown with its own text only.
    children: Vec<Self>,
}

/// One line of a cell that holds its content one element per line.
#[derive(Debug, Clone)]
pub(crate) enum Line {
    /// A piece on its own line.
    Piece(Piece),
    /// An element whose children go one per line between its opening and closing tags.
    Open(Piece),
}

impl Piece {
    /// Bare text.
    pub(crate) const fn text(text: String) -> Self {
        Self {
            tag: None,
            attrs: Vec::new(),
            flag: None,
            text,
            children: Vec::new(),
        }
    }

    /// `text` in a `tag` element without attributes.
    pub(crate) const fn element(tag: &'static str, text: String) -> Self {
        Self {
            tag: Some(tag),
            attrs: Vec::new(),
            flag: None,
            text,
            children: Vec::new(),
        }
    }

    /// `text` in a span of `class`.
    pub(crate) fn span(class: &'static str, text: String) -> Self {
        Self::element("span", text).attr("class", class.to_owned())
    }

    /// A link to `href` reading `text`.
    pub(crate) fn link(href: String, text: String) -> Self {
        Self::element("a", text).attr("href", href)
    }

    /// A time element at `iso` reading `text`, which the page shows in the browser's zone.
    pub(crate) fn time(iso: String, text: String) -> Self {
        Self::element("time", text)
            .attr("datetime", iso)
            .flagged("data-kcc-time")
    }

    /// The piece with the attribute `name` set to `value` after the others; bare text
    /// becomes a span.
    pub(crate) fn attr(mut self, name: &'static str, value: String) -> Self {
        self.tag = Some(self.name());
        self.attrs.push((name, value));
        self
    }

    /// The element with the valueless attribute `name` after the others.
    pub(crate) const fn flagged(mut self, name: &'static str) -> Self {
        self.flag = Some(name);
        self
    }

    /// The element with `child` after its text and earlier children.
    pub(crate) fn with(mut self, child: Self) -> Self {
        self.children.push(child);
        self
    }

    /// The span with an inner span of `class` reading `text` after its text.
    pub(crate) fn with_inner(self, class: &'static str, text: String) -> Self {
        self.with(Self::span(class, text))
    }

    /// The element; none for bare text.
    pub(crate) const fn tag(&self) -> Option<&'static str> {
        self.tag
    }

    /// The element, a span for bare text.
    pub(crate) fn name(&self) -> &'static str {
        self.tag.unwrap_or("span")
    }

    /// Attributes of the element, in output order.
    pub(crate) fn attrs(&self) -> &[(&'static str, String)] {
        &self.attrs
    }

    /// The valueless attribute after the others.
    pub(crate) const fn flag(&self) -> Option<&'static str> {
        self.flag
    }

    /// The text.
    pub(crate) fn content(&self) -> &str {
        &self.text
    }

    /// Elements after the text.
    pub(crate) fn children(&self) -> &[Self] {
        &self.children
    }
}

impl Line {
    /// The piece the line shows.
    pub(crate) const fn piece(&self) -> &Piece {
        match self {
            Self::Piece(piece) | Self::Open(piece) => piece,
        }
    }

    /// Whether the line puts the piece's children one per line.
    pub(crate) const fn is_open(&self) -> bool {
        matches!(self, Self::Open(_))
    }
}
