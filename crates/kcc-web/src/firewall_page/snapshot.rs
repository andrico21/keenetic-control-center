//! The firewall as the router's running configuration has it.
//!
//! The IPv4 and IPv6 access lists with their rules in order and each rule's properties
//! (`rule <index> disable | description | schedule`), and which list each interface
//! applies in which direction. The configuration is read as text, secrets redacted before
//! anything else looks at it, and only access-list and access-group lines are kept.

use core::str;

use kcc_config::{
    config_text::{CliLine, Token, flatten, parse},
    secrets::redact,
};
use kcc_domain::RouterCtx;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;

use super::rule::StoredRule;

/// One rule of a list with its position and properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Position in the list, from 0 as the router counts.
    index: usize,
    /// The stored rule.
    rule: StoredRule,
    /// Whether the rule is disabled.
    disabled: bool,
    /// Description.
    description: Option<String>,
    /// Schedule name.
    schedule: Option<String>,
}

impl Entry {
    /// Position in the list, from 0.
    pub(crate) const fn index(&self) -> usize {
        self.index
    }

    /// The position as people count, from 1.
    pub(crate) const fn position(&self) -> usize {
        self.index.saturating_add(1)
    }

    /// The stored rule.
    pub(crate) const fn rule(&self) -> &StoredRule {
        &self.rule
    }

    /// Whether the rule is disabled.
    pub(crate) const fn disabled(&self) -> bool {
        self.disabled
    }

    /// Description.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Schedule name.
    pub(crate) fn schedule(&self) -> Option<&str> {
        self.schedule.as_deref()
    }
}

/// One access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct List {
    /// The list's name.
    name: String,
    /// Its rules in order.
    entries: Vec<Entry>,
}

impl List {
    /// The list's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Its rules in order.
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The rule at `index`.
    pub(crate) fn entry(&self, index: usize) -> Option<&Entry> {
        self.entries.get(index)
    }
}

/// An access list applied to an interface in one direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    /// The interface.
    interface: String,
    /// The list.
    list: String,
    /// `in` or `out`.
    direction: String,
}

impl Binding {
    /// The binding of `list` to `interface` in `direction`.
    pub(crate) const fn new(interface: String, list: String, direction: String) -> Self {
        Self {
            interface,
            list,
            direction,
        }
    }

    /// The interface.
    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    /// The list.
    pub(crate) fn list(&self) -> &str {
        &self.list
    }

    /// `in` or `out`.
    pub(crate) fn direction(&self) -> &str {
        &self.direction
    }
}

/// The firewall of one router.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// IPv4 access lists, in configuration order.
    lists: Vec<List>,
    /// IPv6 access lists, in configuration order.
    ipv6: Vec<List>,
    /// The lists applied to interfaces.
    bindings: Vec<Binding>,
}

impl Snapshot {
    /// The firewall of the configuration lines `lines`, each split into words.
    pub(crate) fn from_lines(lines: &[Vec<String>]) -> Self {
        let mut snapshot = Self::default();
        let mut ipv4 = Collector::default();
        let mut ipv6 = Collector::default();
        for words in lines {
            match words.as_slice() {
                [access, name, tail @ ..] if access == "access-list" => ipv4.add(name, tail),
                [family, access, name, tail @ ..]
                    if family == "ipv6" && access == "access-list" =>
                {
                    ipv6.add(name, tail);
                }
                [interface, name, ip, group, list, direction]
                    if interface == "interface" && ip == "ip" && group == "access-group" =>
                {
                    snapshot.bindings.push(Binding::new(
                        name.clone(),
                        list.clone(),
                        direction.clone(),
                    ));
                }
                _ => {}
            }
        }
        snapshot.lists = ipv4.finish();
        snapshot.ipv6 = ipv6.finish();
        snapshot
    }

    /// IPv4 access lists.
    pub(crate) fn lists(&self) -> &[List] {
        &self.lists
    }

    /// IPv6 access lists.
    pub(crate) fn ipv6(&self) -> &[List] {
        &self.ipv6
    }

    /// The lists applied to interfaces.
    pub(crate) fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The IPv4 list `name`.
    pub(crate) fn list(&self, name: &str) -> Option<&List> {
        self.lists.iter().find(|list| list.name == name)
    }

    /// The bindings of the list `name`.
    pub(crate) fn bindings_of<'snapshot>(
        &'snapshot self,
        name: &'snapshot str,
    ) -> impl Iterator<Item = &'snapshot Binding> + 'snapshot {
        self.bindings
            .iter()
            .filter(move |binding| binding.list == name)
    }
}

/// The words of configuration lines.
type Lines = Vec<Vec<String>>;

/// Lists being collected from configuration lines.
#[derive(Debug, Default)]
struct Collector {
    /// Names in order of first appearance, with their rule words and property lines.
    lists: Vec<(String, Lines, Lines)>,
}

impl Collector {
    /// Adds the line `tail` of the list `name`: its context alone, a rule or a property.
    fn add(&mut self, name: &str, tail: &[String]) {
        let position = self
            .lists
            .iter()
            .position(|(known, _, _)| known == name)
            .unwrap_or_else(|| {
                self.lists.push((name.to_owned(), Vec::new(), Vec::new()));
                self.lists.len().saturating_sub(1)
            });
        let Some((_, rules, properties)) = self.lists.get_mut(position) else {
            return;
        };
        match tail.first().map(String::as_str) {
            None => {}
            Some("rule") => properties.push(tail.to_vec()),
            Some(_) => rules.push(tail.to_vec()),
        }
    }

    /// The collected lists.
    fn finish(self) -> Vec<List> {
        self.lists
            .into_iter()
            .map(|(name, rules, properties)| List {
                name,
                entries: rules
                    .into_iter()
                    .enumerate()
                    .map(|(index, words)| entry(index, words, &properties))
                    .collect(),
            })
            .collect()
    }
}

/// The rule `words` at `index` with its `properties`.
fn entry(index: usize, words: Vec<String>, properties: &[Vec<String>]) -> Entry {
    let number = index.to_string();
    let value = |keyword: &str| {
        properties.iter().find_map(|line| match line.as_slice() {
            [rule, at, found, value] if rule == "rule" && *at == number && found == keyword => {
                Some(value.clone())
            }
            _ => None,
        })
    };
    Entry {
        index,
        disabled: properties.iter().any(|line| {
            matches!(line.as_slice(), [rule, at, found] if rule == "rule" && *at == number && found == "disable")
        }),
        description: value("description"),
        schedule: value("schedule"),
        rule: StoredRule::new(words),
    }
}

/// The router's firewall, from its running configuration.
///
/// # Errors
///
/// Returns why the configuration could not be read.
// cancel-safe: reads only.
pub(crate) async fn read(domain: &RouterCtx) -> Result<Snapshot, MessageKey> {
    let bytes = domain
        .client
        .download_config(ConfigKind::Running)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "firewall page: running configuration unavailable");
            keys::WEB_KIT_UNREACHABLE
        })?;
    let text = str::from_utf8(bytes.expose_secret()).map_err(|_error| keys::WEB_KIT_FAILED)?;
    let ast = parse(text).map_err(|_error| keys::WEB_KIT_FAILED)?;
    let lines: Vec<Vec<String>> = flatten(&redact(&ast))
        .iter()
        .filter_map(words)
        .filter(|line| {
            line.first()
                .is_some_and(|word| word == "access-list" || word == "ipv6" || word == "interface")
        })
        .collect();
    Ok(Snapshot::from_lines(&lines))
}

/// The words of a configuration line made of plain words only.
fn words(line: &CliLine) -> Option<Vec<String>> {
    line.tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => Some(word.clone()),
            Token::Ns3(_) | _ => None,
        })
        .collect()
}
