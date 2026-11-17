//! The firewall as the router's running configuration stores it.
//!
//! The IPv4 and IPv6 access lists with their rules in order and each rule's properties
//! (`rule <index> disable | description | schedule`), and which list each interface
//! applies in which direction.

use super::{
    model::{ConfiguredRule, Direction},
    rule_list::ListedRule,
    rule_words::StoredRule,
};

/// One rule of an access list with its position and properties.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ListEntry {
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

impl ListEntry {
    /// Position in the list, from 0.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The position as people count, from 1.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.index.saturating_add(1)
    }

    /// The stored rule.
    #[inline]
    #[must_use]
    pub const fn rule(&self) -> &StoredRule {
        &self.rule
    }

    /// Whether the rule is disabled.
    #[inline]
    #[must_use]
    pub const fn disabled(&self) -> bool {
        self.disabled
    }

    /// Description.
    #[inline]
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Schedule name.
    #[inline]
    #[must_use]
    pub fn schedule(&self) -> Option<&str> {
        self.schedule.as_deref()
    }

    /// The rule's full identity for the firewall planner, when it is in the structured
    /// form.
    #[inline]
    #[must_use]
    pub fn configured(&self) -> Option<ConfiguredRule> {
        let form = self.rule.form()?;
        Some(
            ConfiguredRule::new(form.rule(), self.index).with_properties(
                self.disabled,
                self.schedule(),
                self.description(),
            ),
        )
    }

    /// The rule as the firewall planner lists it: its full identity when it is in the
    /// structured form, else its stored words.
    #[inline]
    #[must_use]
    pub fn listed(&self) -> ListedRule {
        ListedRule::new(self.index, self.rule.words().to_vec(), self.configured())
    }
}

/// One access list.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AccessList {
    /// The list's name.
    name: String,
    /// Its rules in order.
    entries: Vec<ListEntry>,
}

impl AccessList {
    /// The list's name.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its rules in order.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[ListEntry] {
        &self.entries
    }

    /// The rule at `index`.
    #[inline]
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<&ListEntry> {
        self.entries.get(index)
    }
}

/// An access list applied to an interface in one direction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Binding {
    /// The interface.
    interface: String,
    /// The list.
    list: String,
    /// The direction.
    direction: Direction,
}

impl Binding {
    /// The binding of `list` to `interface` in `direction`.
    #[inline]
    #[must_use]
    pub const fn new(interface: String, list: String, direction: Direction) -> Self {
        Self {
            interface,
            list,
            direction,
        }
    }

    /// The interface.
    #[inline]
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The list.
    #[inline]
    #[must_use]
    pub fn list(&self) -> &str {
        &self.list
    }

    /// The direction.
    #[inline]
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }
}

/// The firewall of one router.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Firewall {
    /// IPv4 access lists, in configuration order.
    lists: Vec<AccessList>,
    /// IPv6 access lists, in configuration order.
    ipv6: Vec<AccessList>,
    /// The lists applied to interfaces, in configuration order.
    bindings: Vec<Binding>,
}

impl Firewall {
    /// The firewall of the configuration lines `lines`, each split into words; every other
    /// line is ignored.
    pub(crate) fn from_lines(lines: &[Vec<String>]) -> Self {
        let mut firewall = Self::default();
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
                    let way = match direction.as_str() {
                        "in" => Direction::In,
                        "out" => Direction::Out,
                        _ => continue,
                    };
                    firewall
                        .bindings
                        .push(Binding::new(name.clone(), list.clone(), way));
                }
                _ => {}
            }
        }
        firewall.lists = ipv4.finish();
        firewall.ipv6 = ipv6.finish();
        firewall
    }

    /// IPv4 access lists, in configuration order.
    #[inline]
    #[must_use]
    pub fn lists(&self) -> &[AccessList] {
        &self.lists
    }

    /// IPv6 access lists, in configuration order.
    #[inline]
    #[must_use]
    pub fn ipv6(&self) -> &[AccessList] {
        &self.ipv6
    }

    /// The lists applied to interfaces, in configuration order.
    #[inline]
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The IPv4 list `name`.
    #[inline]
    #[must_use]
    pub fn list(&self, name: &str) -> Option<&AccessList> {
        self.lists.iter().find(|list| list.name == name)
    }

    /// The bindings of the IPv4 list `name`.
    #[inline]
    pub fn bindings_of<'firewall>(
        &'firewall self,
        name: &'firewall str,
    ) -> impl Iterator<Item = &'firewall Binding> + 'firewall {
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
    fn finish(self) -> Vec<AccessList> {
        self.lists
            .into_iter()
            .map(|(name, rules, properties)| AccessList {
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
fn entry(index: usize, words: Vec<String>, properties: &[Vec<String>]) -> ListEntry {
    let number = index.to_string();
    let value = |keyword: &str| {
        properties.iter().find_map(|line| match line.as_slice() {
            [rule, at, found, value] if rule == "rule" && *at == number && found == keyword => {
                Some(value.clone())
            }
            _ => None,
        })
    };
    ListEntry {
        index,
        disabled: properties.iter().any(|line| {
            matches!(line.as_slice(), [rule, at, found] if rule == "rule" && *at == number && found == "disable")
        }),
        description: value("description"),
        schedule: value("schedule"),
        rule: StoredRule::new(words),
    }
}
