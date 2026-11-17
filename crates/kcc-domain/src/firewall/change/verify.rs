//! Full-identity firewall read-back verification.
//!
//! Each check reads only the list the change targets. Rule checks are presence checks on
//! the state after the write, so they cannot tell an applied write from an ignored one
//! when the router already held the target state: adding a rule equal to one already in
//! the list, or removing one of two equal rules, passes or fails on the other copy. The
//! preflight refuses a property change or a move whose rule is no longer where it was
//! read.

use super::super::{
    model::{Direction, Rule},
    read,
    rule_list::ListedRule,
};
use crate::{DomainError, Result, RouterCtx};

/// How a firewall change is read back.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Verification {
    /// A rule added to an access list.
    Add {
        /// The access list.
        list: String,
        /// The added rule.
        rule: Rule,
    },
    /// A rule removed from an access list.
    Remove {
        /// The access list.
        list: String,
        /// The removed rule.
        rule: Rule,
    },
    /// A property of one rule changed.
    Property {
        /// The access list.
        list: String,
        /// The rule as it was before the change.
        before: ListedRule,
        /// The changed property.
        property: OwnedRuleProperty,
    },
    /// An access list bound to or unbound from an interface.
    Binding {
        /// The interface.
        interface: String,
        /// The access list.
        list: String,
        /// The traffic direction of the binding.
        direction: Direction,
        /// Whether the binding must be present after the change.
        present: bool,
    },
}

/// A rule property, owned for the read-back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OwnedRuleProperty {
    /// The description; `None` clears it.
    Description(Option<String>),
    /// Whether the rule is disabled.
    Disable(bool),
    /// The schedule; `None` clears it.
    Schedule(Option<String>),
    /// The new position, counted from zero.
    Order(usize),
}

impl Verification {
    /// The protocol of the rule an add or a removal verifies.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidResponse`] for a verification that names no rule.
    pub(super) const fn protocol(&self) -> Result<&str> {
        match self {
            Self::Add { list: _, rule } | Self::Remove { list: _, rule } => {
                Ok(rule.protocol.name())
            }
            Self::Property {
                list: _,
                before: _,
                property: _,
            }
            | Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => Err(DomainError::InvalidResponse),
        }
    }

    /// The property a property change verifies.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidResponse`] for a verification that changes no
    /// property.
    pub(super) const fn property(&self) -> Result<&OwnedRuleProperty> {
        match self {
            Self::Property {
                list: _,
                before: _,
                property,
            } => Ok(property),
            Self::Add { list: _, rule: _ }
            | Self::Remove { list: _, rule: _ }
            | Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => Err(DomainError::InvalidResponse),
        }
    }

    // cancel-safe: only reads; cancellation changes nothing on the router.
    /// The list and the rule of a move.
    pub(super) const fn moved(&self) -> Option<(&str, &ListedRule)> {
        match self {
            Self::Property {
                list,
                before,
                property: OwnedRuleProperty::Order(_),
            } => Some((list.as_str(), before)),
            Self::Property {
                list: _,
                before: _,
                property:
                    OwnedRuleProperty::Description(_)
                    | OwnedRuleProperty::Disable(_)
                    | OwnedRuleProperty::Schedule(_),
            }
            | Self::Add { list: _, rule: _ }
            | Self::Remove { list: _, rule: _ }
            | Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => None,
        }
    }

    /// Checks, before the change, that the rule a removal or property change names is
    /// configured.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::FirewallRuleAbsent`] when it is not, and
    /// [`DomainError::Rci`] or [`DomainError::InvalidResponse`] when the access list
    /// cannot be read.
    pub(super) async fn preflight(&self, router: &RouterCtx) -> Result<()> {
        let present = match self {
            Self::Remove { list, rule } => {
                contains(&read::configured_list(router, list).await?, rule)
            }
            Self::Property {
                list,
                before,
                property: _,
            } => read::configured_list(router, list)
                .await?
                .get(before.index())
                .is_some_and(|found| unchanged(found, before)),
            Self::Add { list: _, rule: _ }
            | Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => true,
        };
        if present {
            Ok(())
        } else {
            Err(DomainError::FirewallRuleAbsent)
        }
    }

    /// Checks a fresh read of the access list or binding against the planned change.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::FirewallVerificationFailed`] when the change is not there,
    /// and [`DomainError::Rci`] or [`DomainError::InvalidResponse`] when the router cannot
    /// be read.
    // cancel-safe: only reads; cancellation changes nothing on the router.
    pub(super) async fn verify(&self, router: &RouterCtx) -> Result<()> {
        let verified = match self {
            Self::Add { list, rule } => contains(&read::configured_list(router, list).await?, rule),
            Self::Remove { list, rule } => {
                !contains(&read::configured_list(router, list).await?, rule)
            }
            Self::Property {
                list,
                before,
                property,
            } => property_holds(
                &read::configured_list(router, list).await?,
                before,
                property,
            ),
            Self::Binding {
                interface,
                list,
                direction,
                present,
            } => read::has_binding(router, interface, list, *direction).await? == *present,
        };
        if verified {
            Ok(())
        } else {
            Err(DomainError::FirewallVerificationFailed)
        }
    }
}

/// Whether `found` is still the rule `before` was read as: the same identity and
/// properties, or the same words for an unstructured rule.
fn unchanged(found: &ListedRule, before: &ListedRule) -> bool {
    before.structured().map_or_else(
        || found.structured().is_none() && found.words() == before.words(),
        |identity| found.structured() == Some(identity),
    )
}

/// Whether `rules` has a structured rule equal to `rule`.
fn contains(rules: &[ListedRule], rule: &Rule) -> bool {
    rules
        .iter()
        .filter_map(ListedRule::structured)
        .any(|found| found.rule == *rule)
}

/// Whether the rule `before` named now carries `property` in `rules`.
fn property_holds(rules: &[ListedRule], before: &ListedRule, property: &OwnedRuleProperty) -> bool {
    let position = match property {
        OwnedRuleProperty::Order(index) => *index,
        OwnedRuleProperty::Description(_)
        | OwnedRuleProperty::Disable(_)
        | OwnedRuleProperty::Schedule(_) => before.index(),
    };
    rules.get(position).is_some_and(|after| {
        after.same_rule(before)
            && match (property, after.structured()) {
                (OwnedRuleProperty::Order(_), _) => true,
                (OwnedRuleProperty::Description(value), Some(found)) => found.description == *value,
                (OwnedRuleProperty::Disable(value), Some(found)) => found.disabled == *value,
                (OwnedRuleProperty::Schedule(value), Some(found)) => found.schedule == *value,
                (
                    OwnedRuleProperty::Description(_)
                    | OwnedRuleProperty::Disable(_)
                    | OwnedRuleProperty::Schedule(_),
                    None,
                ) => false,
            }
    })
}
