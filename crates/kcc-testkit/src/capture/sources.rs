//! Where each learned identifier came from, value-free, for the self-check's diagnostics:
//! the capture item that taught it and the JSON key path inside that item's answer.

use serde_json::Value;

use super::{Captured, INTERFACE_STAT_PREFIX, Raw, Request, detector::Detector};
use crate::anonymize::{
    Identifier, IdentifierKind, fold::fold, learns_from, mac_forms, names_below,
};

/// `len<n>/<class>` of `value`: its length in characters and `non-ascii`, `digits`, `hex`,
/// `ascii-letters` or `mixed`.
pub(crate) fn value_class(value: &str) -> String {
    let class = if !value.is_ascii() {
        "non-ascii"
    } else if value.chars().all(|character| character.is_ascii_digit()) {
        "digits"
    } else if value.chars().all(|character| character.is_ascii_hexdigit()) {
        "hex"
    } else if value
        .chars()
        .all(|character| character.is_ascii_alphabetic())
    {
        "ascii-letters"
    } else {
        "mixed"
    };
    format!("len{}/{class}", value.chars().count())
}

/// For each of `identifiers`, the item of `captured` that first taught it and the place in
/// that item's answer.
///
/// `first` maps identifiers to item indices. A place reads `<item>[<n>].<key>`, router-chosen
/// keys shown as `*`, or `<item>:line <n>`.
pub(crate) fn describe(
    captured: &[Captured],
    first: &[(Identifier, usize)],
    identifiers: &[Identifier],
) -> Vec<String> {
    let detector = Detector::new(identifiers);
    identifiers
        .iter()
        .map(|identifier| {
            let Some((item, result)) = first
                .iter()
                .find(|(known, _)| known == identifier)
                .and_then(|(_, index)| captured.get(*index))
            else {
                return "unknown".to_owned();
            };
            let label = if item.name.starts_with(INTERFACE_STAT_PREFIX) {
                format!("{INTERFACE_STAT_PREFIX}*")
            } else {
                item.name.clone()
            };
            let place = result.as_ref().ok().and_then(|raw| {
                let needles = needles(identifier);
                match &raw.0 {
                    Raw::Json(value) => {
                        let schedule = item.request == Request::Show("show/schedule");
                        let mut search = Search {
                            needles,
                            detector: &detector,
                            schedule,
                            best: [None, None, None, None],
                        };
                        search.walk(value, None, &mut Vec::new());
                        search.best.into_iter().flatten().next()
                    }
                    Raw::Text(text) | Raw::Config(text) => line_of(text, &needles),
                }
            });
            format!(
                "{label}{}",
                place.unwrap_or_else(|| " (place not found)".to_owned())
            )
        })
        .collect()
}

/// The folded spellings of `identifier` as found in an answer.
fn needles(identifier: &Identifier) -> Vec<String> {
    if identifier.kind == IdentifierKind::Mac {
        mac_forms::spellings(&identifier.value).to_vec()
    } else {
        vec![fold(&identifier.value)]
    }
}

/// `:line <n>` of the first line of `text` holding a needle.
fn line_of(text: &str, needles: &[String]) -> Option<String> {
    text.lines()
        .position(|line| {
            let folded = fold(line);
            needles
                .iter()
                .any(|needle| folded.contains(needle.as_str()))
        })
        .map(|index| format!(":line {}", index.saturating_add(1)))
}

/// One step of a JSON path.
enum Segment<'answer> {
    /// An object member; `named` when the object is keyed by names.
    Key(&'answer str, bool),
    /// An array element.
    Index(usize),
}

/// A walk of one JSON answer for the place an identifier was learned.
struct Search<'run> {
    /// The identifier's folded spellings.
    needles: Vec<String>,
    /// Every learned identifier, so no key that holds one is shown.
    detector: &'run Detector<'run>,
    /// Whether the answer is `show schedule`, whose root keys are schedule names.
    schedule: bool,
    /// The first path of each rank: a string under a learning key equal to the value, a
    /// name key equal to it, any string holding it, any key holding it.
    best: [Option<String>; 4],
}

impl Search<'_> {
    /// Walks `value` (under the key `parent`) whose path is `path`.
    fn walk<'answer>(
        &mut self,
        value: &'answer Value,
        parent: Option<&str>,
        path: &mut Vec<Segment<'answer>>,
    ) {
        match value {
            Value::Object(object) => {
                let held = match path.as_slice() {
                    [.., Segment::Key(holder, false), Segment::Key(key, false)] => {
                        names_below(Some(holder), key)
                    }
                    [.., Segment::Key(key, false)] => names_below(None, key),
                    [.., Segment::Key(_, true) | Segment::Index(_)] | [] => false,
                };
                let named =
                    held || (self.schedule && (path.is_empty() || parent == Some("schedule")));
                for (key, member) in object {
                    path.push(Segment::Key(key, named));
                    let folded = fold(key);
                    let rank = if self.equal(&folded) && named {
                        Some(1)
                    } else {
                        self.holds(&folded).then_some(3)
                    };
                    self.record(rank, path, " (key)");
                    self.walk(member, Some(key), path);
                    let _: Option<Segment<'_>> = path.pop();
                }
            }
            Value::Array(members) => {
                for (index, member) in members.iter().enumerate() {
                    path.push(Segment::Index(index));
                    self.walk(member, parent, path);
                    let _: Option<Segment<'_>> = path.pop();
                }
            }
            Value::String(text) => {
                let folded = fold(text);
                let rank = if self.equal(&folded) && parent.is_some_and(learns_from) {
                    Some(0)
                } else {
                    self.holds(&folded).then_some(2)
                };
                self.record(rank, path, "");
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Whether the folded `text` is one of the spellings.
    fn equal(&self, text: &str) -> bool {
        self.needles.iter().any(|needle| needle == text)
    }

    /// Whether the folded `text` holds one of the spellings.
    fn holds(&self, text: &str) -> bool {
        self.needles
            .iter()
            .any(|needle| text.contains(needle.as_str()))
    }

    /// Keeps `path` (with `suffix`) as the place of `rank`, if any, unless one was found
    /// before. A key is shown only when it is firmware-shaped, not a name and holds no
    /// learned value; otherwise it reads `*`.
    fn record(&mut self, rank: Option<usize>, path: &[Segment<'_>], suffix: &str) {
        let detector = self.detector;
        if let Some(slot @ None) = rank.and_then(|index| self.best.get_mut(index)) {
            let mut shown = String::new();
            for segment in path {
                match segment {
                    Segment::Key(key, named) => {
                        let plain =
                            !named && firmware_style(key) && detector.finding(key).is_none();
                        shown.push('.');
                        shown.push_str(if plain { key } else { "*" });
                    }
                    Segment::Index(index) => {
                        shown.push_str(&["[", &index.to_string(), "]"].concat());
                    }
                }
            }
            shown.push_str(suffix);
            *slot = Some(shown);
        }
    }
}

/// Whether `key` looks like a firmware key: lowercase ASCII letters, digits, `-` and `_`,
/// starting with a letter.
fn firmware_style(key: &str) -> bool {
    key.starts_with(|character: char| character.is_ascii_lowercase())
        && key.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_')
        })
}
