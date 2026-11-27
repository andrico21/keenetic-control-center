//! The fidelity check of a written capture: anonymizing changes values, never the router's
//! schema.
//!
//! Each written JSON file is compared with its raw answer, held in memory: the multiset of
//! JSON paths with their kinds must be equal, `[]` standing for an array member. A key may
//! change only where it is the name of an entry of a name-keyed map (the anonymizer's own
//! rule): there the raw key reads `*` unless it is a word of the run's [`Vocabulary`] (kept
//! by the anonymizer), and the written key reads `*` when it is an alias, so a name written
//! as it was fails too. Any other key reads as itself on both sides when it is a plain word
//! (word-shaped, not of a replacement's shape, left alone by the text rules), else `*` (a
//! MAC, an address, an interface id with a `/`): a field rewritten into an alias or with a
//! learned value inside fails, however rare the field is. A redacted secret stands for any
//! scalar of the raw answer. In a configuration text, the keywords of every line (its
//! command path: the first word and the vocabulary words right after it) must be unchanged;
//! the arguments after them are values (a learned comment may hold a vocabulary word).
//!
//! A difference names the file, the first differing place, and the kinds with their counts,
//! never a value: a key in the place is shown only when it is lowercase firmware-shaped and
//! holds no learned identifier.

use alloc::collections::BTreeMap;
use std::{fs, io, path::Path};

use kcc_config::config_text;
use serde_json::Value;

use super::{
    CaptureError, Captured, Raw, Rendered, Request,
    detector::Detector,
    vocabulary::{command, lines},
};
use crate::anonymize::{
    PLACEHOLDER, is_synthetic, names_below, secret_key,
    vocabulary::{Probe, Vocabulary},
};

/// Per path, the count of each JSON kind found there.
type Schema = BTreeMap<String, BTreeMap<&'static str, usize>>;

/// One difference: the place, what the raw answer has there, what the written file has.
type Difference = (String, String, String);

/// Kinds a redacted secret may stand for, tried in this order.
const REDACTABLE: [&str; 2] = ["string", "number"];

/// Which side of the comparison a schema describes.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Side {
    /// The raw answer.
    Raw,
    /// The written file.
    Written,
}

/// What the schema of one side needs besides the value.
struct Reading<'run> {
    /// The side.
    side: Side,
    /// The run's vocabulary: a name equal to one of its words is kept.
    vocabulary: &'run Vocabulary,
    /// Asks whether a key is a plain word.
    probe: Probe,
}

/// Compares every file this run wrote into `directory` with its raw answer in `captured`;
/// on a difference or any error it deletes `directory`.
///
/// # Errors
///
/// [`CaptureError::SchemaChanged`] naming the first file that differs, the place and the
/// kinds; [`CaptureError::Io`] when reading or deleting fails. Either way the directory is
/// deleted first.
#[inline]
pub fn check(
    directory: &Path,
    captured: &[Captured],
    rendered: &Rendered,
) -> Result<(), CaptureError> {
    let outcome = compare(directory, captured, rendered);
    if outcome.is_err() {
        fs::remove_dir_all(directory)?;
    }
    outcome
}

/// The check without the deletion.
///
/// # Errors
///
/// As [`check`].
fn compare(
    directory: &Path,
    captured: &[Captured],
    rendered: &Rendered,
) -> Result<(), CaptureError> {
    let vocabulary = &rendered.vocabulary;
    let detector = Detector::new(&rendered.identifiers);
    for (item, result) in captured {
        let (extension, raw) = match result.as_ref().map(|raw| &raw.0) {
            Ok(raw @ Raw::Json(_)) => ("json", raw),
            Ok(raw @ Raw::Config(_)) => ("txt", raw),
            Ok(Raw::Text(_)) | Err(_) => continue,
        };
        let file = format!("{}.{extension}", item.name);
        if !rendered.files.contains_key(&file) {
            continue;
        }
        let written = fs::read_to_string(directory.join(&file))?;
        let difference = match raw {
            Raw::Json(value) => {
                let parsed: Value = serde_json::from_str(&written).map_err(io::Error::other)?;
                json_difference((value, &parsed), &item.request, vocabulary, &detector)
            }
            Raw::Config(text) => config_difference(text, &written, vocabulary),
            Raw::Text(_) => None,
        };
        if let Some((at, expected, found)) = difference {
            return Err(CaptureError::SchemaChanged {
                item: file,
                at,
                expected,
                found,
            });
        }
    }
    Ok(())
}

/// The first difference between the schemas of the raw answer and the written file of a
/// `request`: first a path of the raw answer the written file does not match, then a path
/// only the written file has.
fn json_difference(
    (raw, written): (&Value, &Value),
    request: &Request,
    vocabulary: &Vocabulary,
    detector: &Detector<'_>,
) -> Option<Difference> {
    let reading = |side| Reading {
        side,
        vocabulary,
        probe: Probe::new(),
    };
    let (mut expected, _) = schema(raw, request, reading(Side::Raw));
    let (found, redacted) = schema(written, request, reading(Side::Written));
    let shown = |path: &str| shown(path, detector);
    for (path, mut count) in redacted {
        let kinds = expected.entry(path.clone()).or_default();
        for kind in REDACTABLE {
            let available = kinds.get(kind).copied().unwrap_or_default();
            let taken = available.min(count);
            count = count.saturating_sub(taken);
            match available.saturating_sub(taken) {
                0 => drop(kinds.remove(kind)),
                left => drop(kinds.insert(kind, left)),
            }
        }
        if count > 0 {
            return Some((shown(&path), "no secret".to_owned(), "redacted".to_owned()));
        }
    }
    expected.retain(|_, kinds| !kinds.is_empty());
    let raw_side = expected.iter().find_map(|(path, kinds)| {
        let there = found.get(path);
        (there != Some(kinds)).then(|| (shown(path), described(Some(kinds)), described(there)))
    });
    raw_side.or_else(|| {
        found
            .iter()
            .find(|(path, _)| !expected.contains_key(*path))
            .map(|(path, kinds)| (shown(path), described(None), described(Some(kinds))))
    })
}

/// The paths and kinds of the answer `value` of `request` as `reading` reads it, and, for
/// the written side, the paths of redacted secrets apart.
fn schema(
    value: &Value,
    request: &Request,
    mut reading: Reading<'_>,
) -> (Schema, BTreeMap<String, usize>) {
    let mut kinds = Schema::new();
    let mut redacted: BTreeMap<String, usize> = BTreeMap::new();
    let mut pending = vec![(value, "$".to_owned(), Holder::root(request, value))];
    while let Some((node, path, holder)) = pending.pop() {
        let kind = match node {
            Value::String(text) if reading.side == Side::Written && text == PLACEHOLDER => {
                let count = redacted.entry(path).or_default();
                *count = count.saturating_add(1);
                continue;
            }
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(members) => {
                pending.extend(members.iter().map(|member| {
                    let inner = Holder::element(holder.secret);
                    (member, format!("{path}[]"), inner)
                }));
                "array"
            }
            Value::Object(object) => {
                for (key, member) in object {
                    let segment = reading.segment(key, holder.named);
                    let inner = holder.below(key, member);
                    pending.push((member, format!("{path}.{segment}"), inner));
                }
                "object"
            }
        };
        let count = kinds.entry(path).or_default().entry(kind).or_default();
        *count = count.saturating_add(1);
    }
    (kinds, redacted)
}

/// Where a JSON value sits, as far as the anonymizer's map rules care.
#[derive(Clone, Copy)]
struct Holder<'value> {
    /// The key holding the value, `None` for a root, an array member or a map entry.
    key: Option<&'value str>,
    /// Whether the value, when an object, is a name-keyed map.
    named: bool,
    /// Whether the value is inside a secret, where no map is name-keyed.
    secret: bool,
}

impl<'value> Holder<'value> {
    /// The root of the answer of `request`: the root of `show schedule` (or the object under
    /// its single `schedule` key) is keyed by schedule names.
    fn root(request: &Request, value: &Value) -> Self {
        let wrapped = |object: &serde_json::Map<String, Value>| {
            object.len() == 1
                && object
                    .get("schedule")
                    .is_some_and(|inner| inner.is_object() || inner.is_array())
        };
        let schedule = matches!(request, Request::Show("show/schedule"))
            && value.as_object().is_some_and(|object| !wrapped(object));
        Self {
            key: None,
            named: schedule,
            secret: false,
        }
    }

    /// An array member inside a secret or not.
    const fn element(secret: bool) -> Self {
        Self {
            key: None,
            named: false,
            secret,
        }
    }

    /// The holder of `member`, held under `key` in this value.
    fn below(self, key: &'value str, member: &Value) -> Self {
        if self.named {
            return Self::element(self.secret);
        }
        let secret = self.secret || secret_key(key);
        Self {
            key: Some(key),
            named: !secret && member.is_object() && names_below(self.key, key),
            secret,
        }
    }
}

impl Reading<'_> {
    /// The path segment of `key`, a key of a name-keyed map when `named`.
    fn segment<'key>(&mut self, key: &'key str, named: bool) -> &'key str {
        let shown = match (named, self.side) {
            (true, Side::Raw) => key.is_empty() || self.vocabulary.holds(key),
            (true, Side::Written) => key.is_empty() || !is_synthetic(key),
            (false, _) => self.probe.plain(key),
        };
        if shown { key } else { "*" }
    }
}

/// The kinds at a path with their counts, `absent` for none.
fn described(kinds: Option<&BTreeMap<&'static str, usize>>) -> String {
    kinds.map_or_else(
        || "absent".to_owned(),
        |found| {
            found
                .iter()
                .map(|(kind, count)| format!("{kind} x{count}"))
                .collect::<Vec<_>>()
                .join("+")
        },
    )
}

/// `path` for a message: a key that is not lowercase firmware-shaped, or that holds a
/// learned identifier, reads `*`.
fn shown(path: &str, detector: &Detector<'_>) -> String {
    path.split('.')
        .map(|segment| {
            let key = segment.trim_end_matches("[]");
            let suffix = segment.get(key.len()..).unwrap_or_default();
            let firmware = key == "$"
                || (key.starts_with(|first: char| first.is_ascii_lowercase())
                    && key.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    })
                    && detector.finding(key).is_none());
            if firmware {
                segment.to_owned()
            } else {
                format!("*{suffix}")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The first line whose keywords differ between the raw and the written configuration.
fn config_difference(raw: &str, written: &str, vocabulary: &Vocabulary) -> Option<Difference> {
    let raw_keywords = keywords(raw, vocabulary)?;
    let Some(written_keywords) = keywords(written, vocabulary) else {
        return Some((
            "whole file".to_owned(),
            "a configuration".to_owned(),
            "text that does not parse".to_owned(),
        ));
    };
    let lines = raw_keywords.len().max(written_keywords.len());
    (0..lines).find_map(|index| {
        let expected = raw_keywords.get(index);
        let found = written_keywords.get(index);
        let at = found.or(expected).map_or_else(
            || "end of file".to_owned(),
            |(line, _)| format!("line {line}"),
        );
        let count = |line: Option<&(usize, Vec<String>)>| {
            line.map_or_else(
                || "no line".to_owned(),
                |(_, words)| format!("{} keywords", words.len()),
            )
        };
        match (expected, found) {
            (Some((_, raw_words)), Some((_, written_words))) if raw_words == written_words => None,
            (Some((_, raw_words)), Some((_, written_words)))
                if raw_words.len() == written_words.len() =>
            {
                let changed = raw_words
                    .iter()
                    .zip(written_words)
                    .position(|(raw_word, written_word)| raw_word != written_word)
                    .unwrap_or_default();
                Some((
                    at,
                    count(expected),
                    format!("keyword {} changed", changed.saturating_add(1)),
                ))
            }
            _ => Some((at, count(expected), count(found))),
        }
    })
}

/// Per configuration line, its line number and keywords: the command word and the
/// vocabulary words right after it; `None` when the text does not parse.
fn keywords(text: &str, vocabulary: &Vocabulary) -> Option<Vec<(usize, Vec<String>)>> {
    let ast = config_text::parse(text).ok()?;
    Some(
        lines(&ast)
            .into_iter()
            .map(|node| {
                let words = command(node)
                    .into_iter()
                    .chain(node.tokens.iter().skip(1).map_while(|token| match token {
                        config_text::Token::Word(word) if vocabulary.is_key(word) => {
                            Some(word.as_str())
                        }
                        config_text::Token::Word(_) | config_text::Token::Ns3(_) | _ => None,
                    }))
                    .map(str::to_owned)
                    .collect();
                (node.line_no, words)
            })
            .collect(),
    )
}

#[cfg(test)]
mod check_tests;
#[cfg(test)]
mod key_tests;
