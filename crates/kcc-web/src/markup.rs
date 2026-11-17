//! HTML a template embeds as it is: only askama's own output.
//!
//! Templates escape every value they write, except a value whose type askama treats as
//! already safe HTML. In this crate that is [`Rendered`], which only rendering a template
//! makes, and the child templates a page embeds (marked with `fragment!` next to
//! `localized!`, which accepts askama templates only). Text, whatever its source, has
//! neither type and is escaped; `cargo xtask assets-check` rejects every other way to
//! write it unescaped.

use core::fmt;

use askama::{Template, filters::HtmlSafe};

/// The output of an askama template, which escaped every value it wrote: safe to embed in
/// another template as it is.
#[derive(Debug, Clone)]
pub(crate) struct Rendered(String);

impl Rendered {
    /// `view` rendered to HTML.
    ///
    /// # Errors
    ///
    /// Returns the [`askama::Error`] of a template that failed to render.
    pub(crate) fn of<T>(view: &T) -> Result<Self, askama::Error>
    where
        T: Template,
    {
        view.render().map(Self)
    }
}

impl fmt::Display for Rendered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl HtmlSafe for Rendered {}
