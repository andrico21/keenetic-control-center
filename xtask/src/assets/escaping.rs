//! Escaping: templates write text only through askama's HTML escaping.
//!
//! A value reaches the page unescaped only when its type is marked as safe HTML, and the
//! web crate marks only askama's own output, in [`MARKERS`]. Every other way to skip
//! the escape is a problem, in any template or web source file: the `safe` filter (also
//! as a `filter` block), the `escape` filter with the `none` escaper, a template whose
//! `escape` setting is `none`, and a safe-HTML marker anywhere else.

use std::path::Path;

use super::{TEMPLATES_DIR, text_files};
use crate::failure::GateError;

/// The web crate's sources, relative to the repository root.
const WEB_SOURCES: &str = "crates/kcc-web/src";

/// The files that may mark a type as safe HTML: the rendered-output type and the macro
/// that marks child templates.
const MARKERS: [&str; 2] = ["crates/kcc-web/src/markup.rs", "crates/kcc-web/src/lib.rs"];

/// The askama trait that marks a type as safe HTML.
const MARKER_TRAIT: &str = "HtmlSafe";

/// Appends a problem for every line of a template or a web source that writes text
/// unescaped.
///
/// # Errors
///
/// Returns [`GateError::Read`] when a directory or a file cannot be read.
pub(super) fn check(root: &Path, problems: &mut Vec<String>) -> Result<(), GateError> {
    let templates = text_files(&root.join(TEMPLATES_DIR), "html")?;
    let sources = text_files(&root.join(WEB_SOURCES), "rs")?;
    for (path, text) in templates.into_iter().chain(sources) {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let shown = relative.display().to_string();
        let may_mark = MARKERS.iter().any(|marker| Path::new(marker) == relative);
        for (index, line) in text.lines().enumerate() {
            if bypasses(line) || (!may_mark && line.contains(MARKER_TRAIT)) {
                let number = index.saturating_add(1);
                problems.push(format!("{shown}: line {number} writes text unescaped"));
            }
        }
    }
    Ok(())
}

/// Whether `line` uses a filter or a setting that skips the HTML escape.
fn bypasses(line: &str) -> bool {
    let compact: String = line.split_whitespace().collect();
    let filters = compact.match_indices('|').filter_map(|(at, _)| {
        compact
            .get(at.saturating_add(1)..)
            .map(|rest| rest.trim_start_matches('('))
    });
    let filter_blocks = compact
        .match_indices("{%filter")
        .chain(compact.match_indices("{%-filter"))
        .filter_map(|(at, opening)| compact.get(at.saturating_add(opening.len())..));
    filters.chain(filter_blocks).any(skips_escape) || compact.contains("escape=\"none\"")
}

/// Whether the filter call at the start of `call` skips the HTML escape: `safe`, or
/// `escape` or `e` with the `none` escaper.
fn skips_escape(call: &str) -> bool {
    let name_end = call
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(call.len());
    let (name, rest) = call.split_at(name_end);
    match name {
        "safe" => true,
        "escape" | "e" => rest.starts_with("(\"none\"") || rest.starts_with("('none'"),
        _ => false,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::bypasses;

    /// Every spelling of an escape bypass is found, and plain output and other filters
    /// are not.
    #[test]
    fn bypasses_are_found_in_every_spelling() {
        for line in [
            "{{ note|safe }}",
            "{{ note | safe }}",
            "{{ note|trim|safe }}",
            "{%- filter safe %}{{ note }}{% endfilter %}",
            "{{ note|escape(\"none\") }}",
            "{{ note|e('none') }}",
            "#[template(ext = \"html\", source = \"{{ x }}\", escape = \"none\")]",
        ] {
            assert!(bypasses(line), "{line}");
        }
        for line in [
            "{{ region }}",
            "{{ note|safe_label }}",
            "{{ note|escape }}",
            "{{ note|e(\"html\") }}",
            "{%- filter upper %}{{ note }}{% endfilter %}",
            "let total = left | right;",
        ] {
            assert!(!bypasses(line), "{line}");
        }
    }
}
