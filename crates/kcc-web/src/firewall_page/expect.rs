//! What the router's firewall must show after a change, checked against a fresh read.

use super::snapshot::{Binding, Snapshot};

/// What the router's firewall must show after a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    /// The list holds the rule `words` exactly `count` times.
    Count {
        /// The list.
        list: String,
        /// The rule's words.
        words: Vec<String>,
        /// How many times.
        count: usize,
    },
    /// The rule `words` stands at `position` of the list.
    At {
        /// The list.
        list: String,
        /// The position, from 0.
        position: usize,
        /// The rule's words.
        words: Vec<String>,
    },
    /// Rule `index` of the list is disabled, or not.
    Disabled {
        /// The list.
        list: String,
        /// The rule's position.
        index: usize,
        /// Whether it is disabled.
        disabled: bool,
    },
    /// Rule `index` of the list has `value` as its description or schedule.
    Property {
        /// The list.
        list: String,
        /// The rule's position.
        index: usize,
        /// `description` or `schedule`.
        keyword: &'static str,
        /// The value; `None` for none.
        value: Option<String>,
    },
    /// The binding is there, or not.
    Bound {
        /// The binding.
        binding: Binding,
        /// Whether it is there.
        present: bool,
    },
}

impl Expect {
    /// Whether `snapshot` shows what the change promised.
    pub(super) fn holds(&self, snapshot: &Snapshot) -> bool {
        match self {
            Self::Count { list, words, count } => {
                let found = snapshot.list(list).map_or(0, |shown| {
                    shown
                        .entries()
                        .iter()
                        .filter(|entry| entry.rule().words() == words.as_slice())
                        .count()
                });
                found == *count
            }
            Self::At {
                list,
                position,
                words,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*position))
                .is_some_and(|entry| entry.rule().words() == words.as_slice()),
            Self::Disabled {
                list,
                index,
                disabled,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*index))
                .is_some_and(|entry| entry.disabled() == *disabled),
            Self::Property {
                list,
                index,
                keyword,
                value,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*index))
                .is_some_and(|entry| {
                    let shown = if *keyword == "description" {
                        entry.description()
                    } else {
                        entry.schedule()
                    };
                    shown == value.as_deref()
                }),
            Self::Bound { binding, present } => snapshot.bindings().contains(binding) == *present,
        }
    }

    /// What a failed read-back names.
    pub(super) fn field(&self) -> String {
        match self {
            Self::Count {
                list,
                words: _,
                count: _,
            }
            | Self::At {
                list,
                position: _,
                words: _,
            }
            | Self::Disabled {
                list,
                index: _,
                disabled: _,
            }
            | Self::Property {
                list,
                index: _,
                keyword: _,
                value: _,
            } => format!("access-list {list}"),
            Self::Bound {
                binding,
                present: _,
            } => format!("interface {} ip access-group", binding.interface()),
        }
    }
}
