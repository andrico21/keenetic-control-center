//! Shared conversion from catalog command words to raw RCI wire segments.

/// Splits a catalog command into its literal keyword segments.
///
/// Instance names are catalog arguments in the body or query, never additional
/// URL segments: `Bridge0` and `WifiMaster0/AccessPoint0` stay in their name slots.
/// This conversion does not establish catalog membership or URL validity.
#[inline]
#[must_use]
pub fn segments(path: &str) -> Vec<String> {
    path.split_whitespace().map(str::to_owned).collect()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::segments;

    /// Whitespace separates keywords, while CLI argument joining has the same inverse.
    #[test]
    fn catalog_words_match_cli_segments() {
        for words in [
            vec!["show", "version"],
            vec!["interface", "description"],
            vec!["show", "interface"],
            Vec::new(),
        ] {
            assert_eq!(segments(&words.join(" ")), words);
        }
        assert_eq!(segments("  show\t interface  "), ["show", "interface"]);
    }
}
