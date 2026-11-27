//! The firmware's own vocabulary: words that are never owner identifiers.
//!
//! A capture learns names from the router's answers (a client's `name`, an SSID, a user
//! name) and replaces them everywhere. A value that equals a word of the firmware's schema
//! (a field the firmware uses at several places, a configuration keyword or a word of the
//! capture's own requests) carries no private information, even when the owner chose it as
//! a name: replacing it would rewrite the schema itself (every `hostname` key, every
//! `ip name-server` line). So such a value is dropped at the moment of learning: it gets no
//! alias, it is never replaced in text, it is not listed by `--identifiers-out` and the
//! self-check does not look for it. A serial is the exception: it is always learned.
//!
//! Only words that the text rules would leave unchanged anyway are admitted (no address, MAC
//! or key shape), so admitting a word never keeps an address or a MAC in the output. Which
//! words a capture run admits is decided in `capture::vocabulary`, so that an owner's name
//! never qualifies.

use alloc::collections::BTreeSet;

use zeroize::Zeroizing;

use super::{Anonymizer, fold::fold, is_synthetic};

/// Words of the firmware's schema and configuration language.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Vocabulary {
    /// Each word in the spelling the firmware uses.
    words: BTreeSet<String>,
    /// Each word folded, for comparing a learned value.
    folded: BTreeSet<String>,
}

impl Vocabulary {
    /// No word.
    pub(super) const fn empty() -> Self {
        Self {
            words: BTreeSet::new(),
            folded: BTreeSet::new(),
        }
    }

    /// The vocabulary of `words`, keeping only word-shaped ones (a letter, then letters,
    /// digits and single `-` or `_` between them) that no text rule would rewrite and that
    /// do not have the shape of an alias.
    #[inline]
    #[must_use]
    pub fn new<I, S>(candidates: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut probe = Probe::new();
        let words: BTreeSet<String> = candidates
            .into_iter()
            .map(|word| word.as_ref().to_owned())
            .filter(|word| is_word_shaped(word) && !is_synthetic(word))
            .filter(|word| probe.unchanged(word))
            .collect();
        let folded = words.iter().map(|word| fold(word)).collect();
        Self { words, folded }
    }

    /// Whether `key` is a vocabulary word in exactly this spelling.
    #[inline]
    #[must_use]
    pub fn is_key(&self, key: &str) -> bool {
        self.words.contains(key)
    }

    /// Whether `value`, as a whole and with Unicode case ignored, is a vocabulary word.
    #[inline]
    #[must_use]
    pub fn holds(&self, value: &str) -> bool {
        self.folded.contains(&fold(value))
    }

    /// The number of words.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether there is no word.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

/// A fresh anonymizer that has learned nothing, for asking whether its text rules would
/// change a word (a dash-spelled MAC, a dashed IPv4 address in a host label).
pub(crate) struct Probe(Anonymizer);

impl Probe {
    /// A probe with a fixed key.
    pub(crate) fn new() -> Self {
        Self(Anonymizer::from_key(Zeroizing::new([0_u8; 64])))
    }

    /// Whether the text rules leave `word` unchanged.
    pub(crate) fn unchanged(&mut self, word: &str) -> bool {
        self.0.text(word).is_ok_and(|kept| kept == word)
    }

    /// Whether `word` is a plain word: word-shaped, not of a replacement's shape and left
    /// unchanged by the text rules.
    pub(crate) fn plain(&mut self, word: &str) -> bool {
        is_word_shaped(word) && !is_synthetic(word) && self.unchanged(word)
    }
}

/// Whether `word` is a letter followed by letters and digits, single `-` or `_` between
/// them, and is not a long run of hex digits (a bare MAC or key).
fn is_word_shaped(word: &str) -> bool {
    let mut characters = word.chars();
    let starts = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic());
    let mut previous_separator = false;
    let body = characters.all(|character| {
        let separator = matches!(character, '-' | '_');
        let fits = character.is_ascii_alphanumeric() || (separator && !previous_separator);
        previous_separator = separator;
        fits
    });
    let hex_run = word.len() >= 8 && word.chars().all(|character| character.is_ascii_hexdigit());
    starts && body && !previous_separator && !hex_run
}
