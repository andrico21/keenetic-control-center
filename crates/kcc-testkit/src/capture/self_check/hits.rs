//! Value-free diagnostics of a refused self-check: where each hit is, what kind of learned
//! value matched, where that value was learned and how long the match is.

use alloc::collections::BTreeSet;
use core::fmt;

use serde_json::Value;

use crate::{
    anonymize::IdentifierKind,
    capture::{Rendered, detector::Detector, sources::value_class},
};

/// Most hits reported per file.
const MAX_HITS_PER_FILE: usize = 10;

/// Stands for the matched text in a shown manifest string.
const MATCH: &str = "<MATCH>";

/// Shown instead of a manifest string whose rest is not made of fixed words.
const REDACTED: &str = "<redacted>";

/// One place where the self-check found a learned or foreign identifier. Every field is
/// value-free: fixed words, positions, kinds and lengths.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LeakHit {
    /// The written file.
    pub file: String,
    /// The place in it: `$.items[<n>].<key>`, `key of $.items[<n>]`, `line <n>` or
    /// `whole file`.
    pub location: String,
    /// The kind of identifier.
    pub kind: IdentifierKind,
    /// Where the matched value was learned (`<item>[<n>].<key>`), or `unlearned`.
    pub source: String,
    /// The learned value's length and character class (`len<n>/<class>`), or `-`.
    pub class: String,
    /// The length of the matched text in characters, when one place could be isolated.
    pub length: Option<usize>,
    /// For the manifest: the matched string with the match as `<MATCH>` when the rest is
    /// made of fixed words and separators, else `<redacted>`.
    pub shown: Option<String>,
}

impl fmt::Display for LeakHit {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file={} at={} kind={} source={} value={} matched-len=",
            self.file, self.location, self.kind, self.source, self.class
        )?;
        match self.length {
            Some(length) => write!(f, "{length}")?,
            None => f.write_str("?")?,
        }
        self.shown
            .as_ref()
            .map_or(Ok(()), |shown| write!(f, " text={shown}"))
    }
}

/// What the diagnostics of one file need.
pub(super) struct Explain<'run> {
    /// The written file's name.
    file: &'run str,
    /// The leak rule.
    detector: &'run Detector<'run>,
    /// The run's identifiers and their sources.
    rendered: &'run Rendered,
}

impl<'run> Explain<'run> {
    /// The diagnostics of `file` under `detector`, with `rendered`'s sources.
    pub(super) const fn new(
        file: &'run str,
        detector: &'run Detector<'run>,
        rendered: &'run Rendered,
    ) -> Self {
        Self {
            file,
            detector,
            rendered,
        }
    }

    /// The hits of the manifest: every router-decided key or string (not in `fixed`) that
    /// leaks, at its JSON path, shown masked when the rest is made of `tokens`.
    pub(super) fn in_manifest(
        &self,
        manifest: &Value,
        fixed: &BTreeSet<String>,
        tokens: &BTreeSet<String>,
    ) -> Vec<LeakHit> {
        let mut hits = Vec::new();
        let mut pending = vec![("$".to_owned(), manifest)];
        while let Some((path, value)) = pending.pop() {
            match value {
                Value::Object(object) => {
                    for (key, member) in object.iter().rev() {
                        let shown = if fixed.contains(key) {
                            key.as_str()
                        } else {
                            "*"
                        };
                        pending.push((format!("{path}.{shown}"), member));
                    }
                    for key in object.keys().filter(|key| !fixed.contains(*key)) {
                        hits.extend(self.word(&format!("key of {path}"), key, tokens));
                    }
                }
                Value::Array(members) => pending.extend(
                    members
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(index, member)| (format!("{path}[{index}]"), member)),
                ),
                Value::String(word) if !fixed.contains(word) => {
                    hits.extend(self.word(&path, word, tokens));
                }
                Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
            if hits.len() >= MAX_HITS_PER_FILE {
                break;
            }
        }
        hits.truncate(MAX_HITS_PER_FILE);
        hits
    }

    /// The hits of a data file, one per leaking line (1-based); its lines are never shown.
    pub(super) fn in_lines(&self, text: &str) -> Vec<LeakHit> {
        text.lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let (kind, learned) = self.detector.finding(line)?;
                let (start, end) = self.span(line);
                let length = line.get(start..end).map(|matched| matched.chars().count());
                let location = format!("line {}", index.saturating_add(1));
                Some(self.hit(location, kind, learned, length, None))
            })
            .take(MAX_HITS_PER_FILE)
            .collect()
    }

    /// The hit for a file that leaks as a whole although no single place does.
    pub(super) fn whole_file(&self, kind: IdentifierKind) -> LeakHit {
        self.hit("whole file".to_owned(), kind, None, None, None)
    }

    /// The hit of one manifest word at `location`, if it leaks.
    fn word(&self, location: &str, word: &str, tokens: &BTreeSet<String>) -> Option<LeakHit> {
        let (kind, learned) = self.detector.finding(word)?;
        let (start, end) = self.span(word);
        let length = word.get(start..end).map(|matched| matched.chars().count());
        let shown = masked(word, start, end, tokens);
        Some(self.hit(location.to_owned(), kind, learned, length, Some(shown)))
    }

    /// A hit with the source and class of the learned identifier at `learned`.
    fn hit(
        &self,
        location: String,
        kind: IdentifierKind,
        learned: Option<usize>,
        length: Option<usize>,
        shown: Option<String>,
    ) -> LeakHit {
        let identifiers = &self.rendered.identifiers;
        let source = learned
            .and_then(|index| self.rendered.sources.get(index))
            .map_or_else(|| "unlearned".to_owned(), Clone::clone);
        let class = learned
            .and_then(|index| identifiers.get(index))
            .map_or_else(
                || "-".to_owned(),
                |identifier| value_class(&identifier.value),
            );
        LeakHit {
            file: self.file.to_owned(),
            location,
            kind,
            source,
            class,
            length,
            shown,
        }
    }

    /// The byte range of a shortest leaking part of `text` (which leaks), found by dropping
    /// characters from the start and then from the end while the rest still leaks.
    fn span(&self, text: &str) -> (usize, usize) {
        let leaks = |part: &str| self.detector.finding(part).is_some();
        let mut start = 0_usize;
        let mut end = text.len();
        while let Some(next) = text.get(start..end).and_then(|rest| rest.chars().next()) {
            let shorter = start.saturating_add(next.len_utf8());
            if !text.get(shorter..end).is_some_and(leaks) {
                break;
            }
            start = shorter;
        }
        while let Some(last) = text
            .get(start..end)
            .and_then(|rest| rest.chars().next_back())
        {
            let shorter = end.saturating_sub(last.len_utf8());
            if !text.get(start..shorter).is_some_and(leaks) {
                break;
            }
            end = shorter;
        }
        (start, end)
    }
}

/// `word` with `start..end` as [`MATCH`] when every other part between the separators
/// `-`, `_`, `.` and `/` is one of `tokens`; [`REDACTED`] otherwise.
fn masked(word: &str, start: usize, end: usize, tokens: &BTreeSet<String>) -> String {
    let (Some(before), Some(after)) = (word.get(..start), word.get(end..)) else {
        return REDACTED.to_owned();
    };
    let fixed = [before, after].into_iter().all(|rest| {
        rest.split(['-', '_', '.', '/'])
            .all(|part| part.is_empty() || tokens.contains(part))
    });
    if fixed {
        format!("{before}{MATCH}{after}")
    } else {
        REDACTED.to_owned()
    }
}
