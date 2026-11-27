//! The firmware's vocabulary of one capture run, from its raw answers before anonymization.
//!
//! The vocabulary decides which learned names are generic words that stay as they are (see
//! [`Vocabulary`]), so an owner's name must never qualify. Its words come from:
//!
//! - the words of the capture's own requests (`ip`, `name-server`, `hotspot`, `user`, ...)
//!   and the first word of every configuration line, which is always a command keyword;
//!   kcc-testkit does not depend on the command catalog, so the catalog is not a source;
//! - field keys. A key counts once per place: the answer (every `show rc` answer and
//!   `rci-root` share one tree) and its path, where an array member reads `[]` and an entry
//!   of a name-keyed map `*`, so the same map read twice is one place. A key is a field
//!   where it is a member of a row (an array member or an entry of a name-keyed map) or where
//!   it holds a scalar or a list of scalars. The keys of a name-keyed map, and of any object
//!   under a key whose values the anonymizer learns (a name, an SSID, a serial, a secret),
//!   are names and never count. A row field at [`MIN_PLACES`] places is a word. A scalar
//!   field at that many places (rows included) is a word only when the run never learns it
//!   as a name: the anonymizer's own learning pass over the run, without a vocabulary,
//!   decides that, so a name an unknown map repeats is never admitted, while a client named
//!   like a row field (`hostname`) or a user named like a keyword (`interface`) stays as it
//!   is.
//!
//! A serial the run learns is never a word, whatever its source.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_config::config_text::{self, Ast, Node, Token};
use serde_json::Value;

use super::{Captured, Item, Raw, Request, anonymize, items};
use crate::anonymize::{
    Anonymizer, IdentifierKind, fold::fold, learns_from, names_below, vocabulary::Vocabulary,
};

/// Fewest distinct places a key must be a field at to be a word.
pub(crate) const MIN_PLACES: usize = 3;

/// Where a key was seen: the answer's tree and the path of the object holding it.
type Place = (String, String);

/// The vocabulary of `captured`.
pub(crate) fn learn(captured: &[Captured]) -> Vocabulary {
    let (names, serials) = learned_names(captured);
    let mut fields = Fields::default();
    let mut words = request_words();
    for (item, result) in captured {
        match result.as_ref().map(|raw| &raw.0) {
            Ok(Raw::Json(value)) => fields.count(item, value),
            Ok(Raw::Config(text)) => {
                if let Ok(ast) = config_text::parse(text) {
                    words.extend(
                        lines(&ast)
                            .into_iter()
                            .filter_map(command)
                            .map(str::to_owned),
                    );
                }
            }
            Ok(Raw::Text(_)) | Err(_) => {}
        }
    }
    words.extend(fields.words(&names));
    Vocabulary::new(
        words
            .into_iter()
            .filter(|word| !serials.contains(&fold(word))),
    )
}

/// The folded names and serials the anonymizer learns from `captured` when no word is
/// generic.
fn learned_names(captured: &[Captured]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut dry = Anonymizer::new();
    for (item, result) in captured {
        if let Ok(raw) = result {
            drop(anonymize(&mut dry, item, raw));
        }
    }
    let mut names = BTreeSet::new();
    let mut serials = BTreeSet::new();
    for identifier in dry.identifiers() {
        let set = match identifier.kind {
            IdentifierKind::Serial => &mut serials,
            IdentifierKind::Host
            | IdentifierKind::Ssid
            | IdentifierKind::User
            | IdentifierKind::Schedule => &mut names,
            IdentifierKind::Secret | IdentifierKind::Mac | IdentifierKind::Address => {
                continue;
            }
        };
        let _: bool = set.insert(fold(&identifier.value));
    }
    (names, serials)
}

/// How the keys of one object are read.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Keys {
    /// Names of a name-keyed map: never counted.
    Names,
    /// Fields of a row.
    Row,
    /// Keys of any other object: fields where they hold a scalar.
    Other,
}

/// The places of every field key of a run.
#[derive(Default)]
struct Fields<'run> {
    /// Per key, the places it is a member of a row.
    rows: BTreeMap<&'run str, BTreeSet<Place>>,
    /// Per key, the places it holds a scalar or a list of scalars outside a row.
    scalars: BTreeMap<&'run str, BTreeSet<Place>>,
}

impl<'run> Fields<'run> {
    /// Counts the field keys of the answer `value` of `item`.
    fn count(&mut self, item: &Item, value: &'run Value) {
        let tree = match item.request {
            Request::Root | Request::ShowRc(_) => "rci-root".to_owned(),
            Request::Show(_)
            | Request::Get(_)
            | Request::RunningConfig
            | Request::ShowLog
            | Request::Continued(..)
            | Request::InterfaceStat(_) => item.name.clone(),
        };
        let (start, reading) = root(&item.request, value);
        let mut pending: Vec<(&Value, String, Option<&str>, Keys)> =
            vec![(start, "$".to_owned(), None, reading)];
        while let Some((node, path, holder, keys)) = pending.pop() {
            match node {
                Value::Object(object) => {
                    for (key, member) in object {
                        let place = || (tree.clone(), path.clone());
                        match keys {
                            Keys::Row => {
                                let _: bool = self.rows.entry(key).or_default().insert(place());
                            }
                            Keys::Other if scalar(member) => {
                                let _: bool = self.scalars.entry(key).or_default().insert(place());
                            }
                            Keys::Names | Keys::Other => {}
                        }
                        let (segment, below, inner) = match keys {
                            Keys::Names => ("*", None, Keys::Row),
                            Keys::Row | Keys::Other
                                if names_below(holder, key) || learns_from(key) =>
                            {
                                (key.as_str(), Some(key.as_str()), Keys::Names)
                            }
                            Keys::Row | Keys::Other => {
                                (key.as_str(), Some(key.as_str()), Keys::Other)
                            }
                        };
                        pending.push((member, format!("{path}.{segment}"), below, inner));
                    }
                }
                Value::Array(members) => pending.extend(
                    members
                        .iter()
                        .map(|member| (member, format!("{path}[]"), None, Keys::Row)),
                ),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
    }

    /// The keys that are words: a row field at [`MIN_PLACES`] places, or a field at that
    /// many places that is not one of the run's learned `names`.
    fn words(&self, names: &BTreeSet<String>) -> Vec<String> {
        let empty = BTreeSet::new();
        self.rows
            .keys()
            .chain(self.scalars.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|key| {
                let rows = self.rows.get(**key).unwrap_or(&empty);
                let scalars = self.scalars.get(**key).unwrap_or(&empty);
                rows.len() >= MIN_PLACES
                    || (!names.contains(&fold(key)) && rows.union(scalars).count() >= MIN_PLACES)
            })
            .map(|key| (*key).to_owned())
            .collect()
    }
}

/// Whether `value` is a scalar or a list of scalars.
fn scalar(value: &Value) -> bool {
    match value {
        Value::Object(_) => false,
        Value::Array(members) => members
            .iter()
            .all(|member| !matches!(member, Value::Object(_) | Value::Array(_))),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

/// Every command line of `ast`, parents before their children, in text order.
pub(crate) fn lines(ast: &Ast) -> Vec<&Node> {
    let mut ordered = Vec::new();
    let mut pending: Vec<&Node> = ast.nodes.iter().rev().collect();
    while let Some(node) = pending.pop() {
        ordered.push(node);
        pending.extend(node.children.iter().rev());
    }
    ordered
}

/// The command word of a configuration line: its first word.
pub(crate) fn command(node: &Node) -> Option<&str> {
    match node.tokens.first() {
        Some(Token::Word(word)) => Some(word.as_str()),
        Some(Token::Ns3(_) | _) | None => None,
    }
}

/// Where the keys of an answer start and how they are read: the root of `show schedule`
/// (or the object under its single `schedule` key) is keyed by schedule names.
fn root<'value>(request: &Request, value: &'value Value) -> (&'value Value, Keys) {
    if !matches!(request, Request::Show("show/schedule")) {
        return (value, Keys::Other);
    }
    match value
        .as_object()
        .map(|object| (object.len(), object.get("schedule")))
    {
        Some((1, Some(inner))) if inner.is_object() => (inner, Keys::Names),
        Some((1, Some(inner))) => (inner, Keys::Other),
        Some(_) | None => (value, Keys::Names),
    }
}

/// The words of the capture's own requests: path segments and `show rc` command words.
fn request_words() -> Vec<String> {
    items()
        .into_iter()
        .flat_map(|item| match item.request {
            Request::Show(path) | Request::Get(path) | Request::Continued(path, _, _) => {
                path.split('/').map(str::to_owned).collect()
            }
            Request::ShowRc(paths) => paths
                .iter()
                .flat_map(|path| path.split(' '))
                .map(str::to_owned)
                .collect(),
            Request::Root
            | Request::RunningConfig
            | Request::ShowLog
            | Request::InterfaceStat(_) => Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod learn_tests;
#[cfg(test)]
mod name_tests;
