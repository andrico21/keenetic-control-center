//! Text from a router's userland made inert for a result: no terminal escape sequence,
//! control character or bidirectional override survives.

use core::{iter::Peekable, str::Chars};

/// `text` without ANSI escape sequences (CSI and OSC included), control characters and
/// Unicode bidirectional overrides or isolates.
pub(crate) fn plain(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\u{1b}' => skip_escape(&mut characters),
            _ if character.is_control() || is_bidi(character) => {}
            _ => kept.push(character),
        }
    }
    kept
}

/// [`plain`] text of `text` cut to its first `max_chars` characters, and whether it was
/// cut.
pub(crate) fn bounded(text: &str, max_chars: usize) -> (String, bool) {
    let kept = plain(text);
    match kept.char_indices().nth(max_chars) {
        Some((end, _)) => (kept.get(..end).unwrap_or_default().to_owned(), true),
        None => (kept, false),
    }
}

/// Skips the rest of an escape sequence whose `ESC` was just read: a CSI sequence up to
/// its final byte, an OSC string up to its terminator, or the one character after `ESC`.
fn skip_escape(characters: &mut Peekable<Chars<'_>>) {
    match characters.next() {
        Some('[') => {
            while characters
                .next_if(|next| !('\u{40}'..='\u{7e}').contains(next))
                .is_some()
            {}
            let _: Option<char> = characters.next();
        }
        Some(']') => {
            while characters
                .next_if(|next| *next != '\u{7}' && *next != '\u{1b}')
                .is_some()
            {}
        }
        Some(_) | None => {}
    }
}

/// Whether `character` overrides or isolates the text direction.
const fn is_bidi(character: char) -> bool {
    matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test code fails by panicking")]
mod tests {
    use super::{bounded, plain};

    /// Todo 17: text longer than the bound is cut at a character boundary and reported
    /// cut; text within it is kept whole; the bound counts characters after cleaning.
    #[test]
    fn bounded_cuts_at_a_character_boundary() {
        for (raw, max, expected) in [
            ("abcdef", 3, ("abc", true)),
            ("abc", 3, ("abc", false)),
            ("\u{e9}\u{e9}\u{e9}\u{e9}", 2, ("\u{e9}\u{e9}", true)),
            ("a\u{1b}[31mbc\u{7}", 3, ("abc", false)),
        ] {
            let (kept, cut) = bounded(raw, max);
            assert_eq!((kept.as_str(), cut), expected, "{raw:?}");
        }
    }

    /// Escape sequences, control characters and direction overrides are removed; other
    /// text, non-ASCII letters included, is kept.
    #[test]
    fn only_inert_text_remains() {
        for (raw, expected) in [
            ("1.0\u{1b}[31m\u{7}-1", "1.0-1"),
            ("a\u{1b}[1;37m b\u{1b}[m", "a b"),
            ("x\u{1b}]0;title\u{7}y", "xy"),
            ("tab\there\nnew\r", "tabherenew"),
            ("\u{9b}c\u{202e}d\u{2066}", "cd"),
            ("caf\u{e9} 7.2-1", "caf\u{e9} 7.2-1"),
            ("end\u{1b}", "end"),
        ] {
            assert_eq!(plain(raw), expected, "{raw:?}");
        }
    }
}
