//! Access-list rules as the RCI running configuration lists them.
//!
//! A rule in the form the planner writes (`permit | deny <protocol> <source> <mask>
//! [port eq N | port range N M] <destination> <mask> [port ...]`) is read with its full
//! identity; a rule in any other form is unstructured and keeps only its words and its
//! position, so one rule the planner does not model never hides the rest of its list.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private access-list decoders are narrowly named"
    )
)]

use serde_json::Value;

use super::model::{Action, ConfiguredRule, Protocol, Rule};
use crate::{DomainError, Result};

/// One rule of an access list, in the order the router counts.
///
/// It keeps its stored words, and its full identity when it is in the form the planner
/// writes. A rule without that identity is unstructured: it is moved as its words, never
/// changed field by field.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ListedRule {
    /// Position in the access list, counted from zero.
    index: usize,
    /// The words after `access-list <name>`.
    words: Vec<String>,
    /// The full identity, for a rule in the planner's form.
    configured: Option<ConfiguredRule>,
}

impl ListedRule {
    /// The rule at `index` stored as `words`, with its identity when it has one.
    pub(crate) const fn new(
        index: usize,
        words: Vec<String>,
        configured: Option<ConfiguredRule>,
    ) -> Self {
        Self {
            index,
            words,
            configured,
        }
    }

    /// Position in the access list, counted from zero.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The words after `access-list <name>`.
    #[inline]
    #[must_use]
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// The full identity of a rule in the planner's form; `None` for an unstructured
    /// rule.
    #[inline]
    #[must_use]
    pub const fn structured(&self) -> Option<&ConfiguredRule> {
        self.configured.as_ref()
    }

    /// Whether `self` and `other` are the same stored rule, ignoring position and
    /// properties.
    pub(crate) fn same_rule(&self, other: &Self) -> bool {
        match (&self.configured, &other.configured) {
            (Some(left), Some(right)) => left.rule == right.rule,
            (None | Some(_), None | Some(_)) => self.words == other.words,
        }
    }
}

/// The rules of one list's `show rc` rows, in order.
///
/// # Errors
///
/// Returns `InvalidResponse` when the rows are not arrays of words.
pub(crate) fn parse_list(value: &Value) -> Result<Vec<ListedRule>> {
    let rows = value.as_array().ok_or(DomainError::InvalidResponse)?;
    let mut rules = Vec::new();
    let mut properties = Vec::new();
    for row in rows {
        let command = row
            .get("command")
            .and_then(Value::as_array)
            .ok_or(DomainError::InvalidResponse)?
            .iter()
            .map(|word| {
                word.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or(DomainError::InvalidResponse)
            })
            .collect::<Result<Vec<_>>>()?;
        if command.is_empty() {
            continue;
        }
        if command.first().is_some_and(|word| word == "rule") {
            properties.push(command);
        } else {
            rules.push(command);
        }
    }
    Ok(rules
        .into_iter()
        .enumerate()
        .map(|(index, words)| listed_rule(index, words, &properties))
        .collect())
}

fn listed_rule(index: usize, words: Vec<String>, properties: &[Vec<String>]) -> ListedRule {
    let number = index.to_string();
    let property = |name: &str| {
        properties.iter().find_map(|line| match line.as_slice() {
            [keyword, at, found, value] if keyword == "rule" && at == &number && found == name => {
                Some(value.as_str())
            }
            _ => None,
        })
    };
    let disabled = properties.iter().any(|line| {
        matches!(line.as_slice(), [keyword, at, field] if keyword == "rule" && at == &number && field == "disable")
    });
    let configured = parse_rule(&words).map(|rule| {
        ConfiguredRule::new(rule, index).with_properties(
            disabled,
            property("schedule"),
            property("description"),
        )
    });
    ListedRule::new(index, words, configured)
}

fn parse_rule(words: &[String]) -> Option<Rule> {
    let [action_word, protocol_word, rest @ ..] = words else {
        return None;
    };
    let action = match action_word.as_str() {
        "permit" => Action::Permit,
        "deny" => Action::Deny,
        _ => return None,
    };
    let protocol = match protocol_word.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "esp" => Protocol::Esp,
        "gre" => Protocol::Gre,
        "ipip" => Protocol::IpIp,
        "ip" => Protocol::Ip,
        _ => return None,
    };
    let (source, source_port, destination_words) = side(rest)?;
    let (destination, destination_port, tail) = side(destination_words)?;
    if !tail.is_empty() {
        return None;
    }
    let mut rule = Rule::new(action, protocol, source.0, destination.0);
    source.1.clone_into(&mut rule.source_mask);
    destination.1.clone_into(&mut rule.destination_mask);
    (rule.source_port, rule.source_end_port) = source_port;
    (rule.destination_port, rule.destination_end_port) = destination_port;
    Some(rule)
}

/// An address and mask, the optional port and range end, and the words after them.
type ParsedSide<'words> = (
    (&'words str, &'words str),
    (Option<u16>, Option<u16>),
    &'words [String],
);

fn side(words: &[String]) -> Option<ParsedSide<'_>> {
    let [address, mask, rest @ ..] = words else {
        return None;
    };
    let (ports, tail) = match rest {
        [keyword, operator, value, tail @ ..] if keyword == "port" && operator == "eq" => {
            ((Some(value.parse().ok()?), None), tail)
        }
        [keyword, range, start, end, tail @ ..] if keyword == "port" && range == "range" => {
            ((Some(start.parse().ok()?), Some(end.parse().ok()?)), tail)
        }
        [keyword, ..] if keyword == "port" => return None,
        _ => ((None, None), rest),
    };
    Some(((address.as_str(), mask.as_str()), ports, tail))
}
