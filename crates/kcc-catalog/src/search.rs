//! Tokenized catalog search over command paths, arguments, and project-owned synonyms.

use alloc::collections::BTreeMap;
use core::iter;
use std::sync::LazyLock;

use serde::Deserialize;

use crate::Command;

/// One ranked catalog search match.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SearchResult<'catalog> {
    /// Matched command.
    pub command: &'catalog Command,
    /// Relative integer rank; larger values are better.
    pub score: usize,
}

/// Deserialized synonym file.
#[derive(Deserialize)]
struct SynonymTable {
    /// English synonyms.
    en: BTreeMap<String, Vec<String>>,
    /// Russian synonyms.
    ru: BTreeMap<String, Vec<String>>,
    /// Ukrainian synonyms.
    uk: BTreeMap<String, Vec<String>>,
    /// German synonyms.
    de: BTreeMap<String, Vec<String>>,
    /// Belarusian synonyms.
    be: BTreeMap<String, Vec<String>>,
    /// Kazakh synonyms.
    kk: BTreeMap<String, Vec<String>>,
}

/// All locale entries indexed by normalized query phrase.
static SYNONYMS: LazyLock<BTreeMap<String, Vec<String>>> = LazyLock::new(|| {
    let parsed = toml::from_str::<SynonymTable>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../catalog/synonyms.toml"
    )))
    .unwrap_or_else(|_error| SynonymTable {
        en: BTreeMap::new(),
        ru: BTreeMap::new(),
        uk: BTreeMap::new(),
        de: BTreeMap::new(),
        be: BTreeMap::new(),
        kk: BTreeMap::new(),
    });
    let SynonymTable {
        en,
        ru,
        uk,
        de,
        be,
        kk,
    } = parsed;
    en.into_iter()
        .chain(ru)
        .chain(uk)
        .chain(de)
        .chain(be)
        .chain(kk)
        .collect()
});

/// Converts punctuation-separated text into lowercase search tokens.
pub(crate) fn tokenize(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Adds synonym targets for exact query phrases and individual terms.
pub(crate) fn expand(query_tokens: &[String]) -> Vec<String> {
    let phrase = query_tokens.join(" ");
    let mut expanded = Vec::new();
    for key in iter::once(&phrase).chain(query_tokens) {
        if let Some(values) = SYNONYMS.get(key) {
            for value in values {
                expanded.extend(tokenize(value));
            }
        }
    }
    expanded
}

/// Scores direct path/argument tokens above synonym-only matches.
pub(crate) fn score(
    command: &Command,
    query_tokens: &[String],
    expanded: &[String],
) -> Option<usize> {
    let path_tokens = tokenize(&command.path);
    let argument_tokens = command
        .arguments
        .keys()
        .flat_map(|argument| tokenize(argument))
        .collect::<Vec<_>>();
    let direct = query_tokens
        .iter()
        .map(|query| {
            token_score(query, &path_tokens, 12).saturating_add(token_score(
                query,
                &argument_tokens,
                6,
            ))
        })
        .sum::<usize>();
    let synonym_phrase_bonus = if SYNONYMS
        .get(&query_tokens.join(" "))
        .is_some_and(|targets| {
            targets.iter().any(|target| {
                command.path == *target || command.path.starts_with(&format!("{target} "))
            })
        }) {
        64
    } else {
        0
    };
    let synonym = expanded
        .iter()
        .map(|query| {
            token_score(query, &path_tokens, 8).saturating_add(token_score(
                query,
                &argument_tokens,
                4,
            ))
        })
        .sum::<usize>();
    direct
        .checked_add(synonym)?
        .checked_add(synonym_phrase_bonus)
}

/// Gives exact token matches twice the weight of prefixes.
fn token_score(query: &str, candidates: &[String], weight: usize) -> usize {
    candidates.iter().fold(0, |best, candidate| {
        let current = if candidate == query {
            weight.saturating_mul(2)
        } else if candidate.starts_with(query) || query.starts_with(candidate) {
            weight
        } else {
            0
        };
        best.max(current)
    })
}
