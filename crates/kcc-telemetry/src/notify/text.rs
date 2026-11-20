//! Message length rules of the Bot API.

/// Longest message kcc sends: both its character count and its UTF-16 length stay
/// within this, since the Bot API documentation does not say which one it counts.
pub const MAX_MESSAGE: usize = 4096;

/// Appended to a text that [`fit`] had to cut.
const ELLIPSIS: char = '\u{2026}';

/// Whether `text` is within [`MAX_MESSAGE`] in characters and in UTF-16 units.
#[inline]
#[must_use]
pub fn fits(text: &str) -> bool {
    text.chars().count() <= MAX_MESSAGE && text.encode_utf16().count() <= MAX_MESSAGE
}

/// Returns `text` unchanged when it [`fits`]; otherwise its longest prefix, cut at a
/// character boundary, that fits together with a trailing ellipsis.
#[inline]
#[must_use]
pub fn fit(text: &str) -> String {
    if fits(text) {
        return text.to_owned();
    }
    let room = MAX_MESSAGE.saturating_sub(1);
    let mut cut = String::with_capacity(text.len().min(MAX_MESSAGE.saturating_mul(4)));
    let mut chars = 0_usize;
    let mut units = 0_usize;
    for character in text.chars() {
        chars = chars.saturating_add(1);
        units = units.saturating_add(character.len_utf16());
        if chars > room || units > room {
            break;
        }
        cut.push(character);
    }
    cut.push(ELLIPSIS);
    cut
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use super::{MAX_MESSAGE, fit, fits};

    /// A short text is kept as it is.
    #[test]
    fn short_text_is_kept() {
        assert_eq!(
            fit("router home is down"),
            "router home is down",
            "unchanged"
        );
    }

    /// Todo 8: a long ASCII text is cut by characters and ends with the ellipsis.
    #[test]
    fn long_ascii_is_cut_to_the_character_limit() {
        let text = "a".repeat(5000);
        let cut = fit(&text);
        assert_eq!(cut.chars().count(), MAX_MESSAGE, "char count at the limit");
        assert!(cut.ends_with('\u{2026}'), "ellipsis appended");
        assert!(fits(&cut), "the cut text fits");
    }

    /// Todo 8: emoji count twice in UTF-16, so the UTF-16 length decides the cut.
    #[test]
    fn emoji_text_is_cut_to_the_utf16_limit() {
        let text = "\u{1F600}".repeat(3000);
        let cut = fit(&text);
        assert!(
            cut.encode_utf16().count() <= MAX_MESSAGE,
            "UTF-16 within limit"
        );
        assert_eq!(
            cut.encode_utf16().count(),
            MAX_MESSAGE.saturating_sub(1),
            "cut at the last whole emoji"
        );
        assert!(cut.ends_with('\u{2026}'), "ellipsis appended");
    }

    /// A text exactly at both limits is not cut.
    #[test]
    fn text_at_the_limit_is_kept() {
        let text = "b".repeat(MAX_MESSAGE);
        assert_eq!(fit(&text), text, "unchanged at the limit");
    }
}
