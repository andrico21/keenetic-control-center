//! Unicode case-insensitive matching of learned values in text, shared by the anonymizer
//! and the capture self-check so both apply the same rule.
//!
//! Every value and every text are compared after [`fold`]. A value of at least
//! [`ANYWHERE_MIN_CHARS`] characters matches anywhere, glued to other words included; a
//! shorter one matches only as a whole word, so ordinary words that merely contain it (and
//! the anonymizer's own `host-N` aliases) do not.

use core::str::from_utf8;

/// Shortest folded value, in characters, that matches anywhere.
pub(crate) const ANYWHERE_MIN_CHARS: usize = 6;

/// `text` lowercased character by character with the Unicode lowercase mapping; every
/// learned value and every text it is looked for in are compared in this form.
pub(crate) fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

/// Whether `character` continues a word: a letter or digit of any script, `-` or `_`.
fn is_word(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '-' | '_')
}

/// Whether `text[start..end]` has no word character right before or after it.
fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).and_then(|head| head.chars().next_back());
    let after = text.get(end..).and_then(|tail| tail.chars().next());
    !before.is_some_and(is_word) && !after.is_some_and(is_word)
}

/// Whether the folded `needle` occurs in the folded `haystack` under the matching rule.
pub(crate) fn contains_folded(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let anywhere = needle.chars().count() >= ANYWHERE_MIN_CHARS;
    haystack.match_indices(needle).any(|(start, found)| {
        anywhere || stands_alone(haystack, start, start.saturating_add(found.len()))
    })
}

/// `text` with every `%XX` escape decoded and `+` read as a space; bytes that do not form
/// UTF-8 become U+FFFD.
pub(crate) fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        let escaped = bytes
            .get(index.saturating_add(1)..index.saturating_add(3))
            .filter(|hex| byte == b'%' && hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(value) = escaped {
            decoded.push(value);
            index = index.saturating_add(3);
        } else {
            decoded.push(if byte == b'+' { b' ' } else { byte });
            index = index.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// One learned value and its replacement, prepared for [`replace_all`].
pub(crate) struct Learned<'value> {
    /// The value as the router sent it.
    original: &'value str,
    /// [`fold`] of `original`, as characters.
    folded: Vec<char>,
    /// What replaces it.
    replacement: &'value str,
}

impl<'value> Learned<'value> {
    /// Prepares `original`; `None` for an empty value, which matches nothing.
    pub(crate) fn new(original: &'value str, replacement: &'value str) -> Option<Self> {
        (!original.is_empty()).then(|| Self {
            original,
            folded: fold(original).chars().collect(),
            replacement,
        })
    }

    /// Length of the folded value in characters; longer values are tried first.
    pub(crate) const fn folded_len(&self) -> usize {
        self.folded.len()
    }

    /// Byte end of a match of this value starting at byte `start` of `text`: its exact
    /// spelling anywhere, or any case under the matching rule.
    fn match_at(&self, text: &str, start: usize) -> Option<usize> {
        let rest = text.get(start..)?;
        if rest.starts_with(self.original) {
            return Some(start.saturating_add(self.original.len()));
        }
        let mut expected = self.folded.iter();
        for (offset, character) in rest.char_indices() {
            for lower in character.to_lowercase() {
                if expected.next() != Some(&lower) {
                    return None;
                }
            }
            if expected.as_slice().is_empty() {
                let end = start
                    .saturating_add(offset)
                    .saturating_add(character.len_utf8());
                let anywhere = self.folded.len() >= ANYWHERE_MIN_CHARS;
                return (anywhere || stands_alone(text, start, end)).then_some(end);
            }
        }
        None
    }
}

/// Replaces every match of `learned` (tried in the given order at each position) in one
/// left-to-right pass, so a replacement is never matched again.
pub(crate) fn replace_all(text: &str, learned: &[Learned<'_>]) -> String {
    let mut output = String::with_capacity(text.len());
    let mut position = 0_usize;
    while let Some(next) = text.get(position..).and_then(|rest| rest.chars().next()) {
        let found = learned
            .iter()
            .find_map(|value| Some((value.match_at(text, position)?, value.replacement)));
        if let Some((end, replacement)) = found {
            output.push_str(replacement);
            position = end;
        } else {
            output.push(next);
            position = position.saturating_add(next.len_utf8());
        }
    }
    output
}
