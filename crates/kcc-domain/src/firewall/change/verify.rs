//! Full-identity firewall read-back verification.

use alloc::collections::BTreeMap;

use super::super::{
    model::{ConfiguredRule, Direction, Rule},
    read,
};
use crate::{DomainError, Result, RouterCtx};

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Verification {
    Add {
        list: String,
        rule: Rule,
    },
    Remove {
        list: String,
        rule: Rule,
    },
    Property {
        list: String,
        before: ConfiguredRule,
        property: OwnedRuleProperty,
    },
    Binding {
        interface: String,
        list: String,
        direction: Direction,
        present: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OwnedRuleProperty {
    Description(Option<String>),
    Disable(bool),
    Schedule(Option<String>),
    Order(usize),
}

impl Verification {
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

    pub(super) async fn preflight(&self, router: &RouterCtx) -> Result<()> {
        match self {
            Self::Remove { list, rule } => {
                let rules = read::configured_rules(router).await?;
                if !contains(&rules, list, rule) {
                    return Err(DomainError::FirewallRuleAbsent);
                }
                Ok(())
            }
            Self::Property {
                list,
                before,
                property: _,
            } => {
                let rules = read::configured_rules(router).await?;
                if !rules
                    .get(list)
                    .and_then(|configured| configured.get(before.index))
                    .is_some_and(|found| found == before)
                {
                    return Err(DomainError::FirewallRuleAbsent);
                }
                Ok(())
            }
            Self::Add { list: _, rule: _ }
            | Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => Ok(()),
        }
    }

    pub(super) async fn verify(&self, router: &RouterCtx) -> Result<()> {
        let rules = read::configured_rules(router).await?;
        let verified = match self {
            Self::Add { list, rule } => contains(&rules, list, rule),
            Self::Remove { list, rule } => !contains(&rules, list, rule),
            Self::Property {
                list,
                before,
                property,
            } => property_holds(&rules, list, before, property),
            Self::Binding {
                interface: _,
                list: _,
                direction: _,
                present: _,
            } => true,
        };
        if verified {
            Ok(())
        } else {
            Err(DomainError::FirewallVerificationFailed)
        }
    }
}

fn contains(lists: &BTreeMap<String, Vec<ConfiguredRule>>, list: &str, rule: &Rule) -> bool {
    lists
        .get(list)
        .is_some_and(|rules| rules.iter().any(|found| found.rule == *rule))
}

fn property_holds(
    lists: &BTreeMap<String, Vec<ConfiguredRule>>,
    list: &str,
    before: &ConfiguredRule,
    property: &OwnedRuleProperty,
) -> bool {
    let position = match property {
        OwnedRuleProperty::Order(index) => *index,
        OwnedRuleProperty::Description(_)
        | OwnedRuleProperty::Disable(_)
        | OwnedRuleProperty::Schedule(_) => before.index,
    };
    lists
        .get(list)
        .and_then(|rules| rules.get(position))
        .is_some_and(|after| {
            after.rule == before.rule
                && match property {
                    OwnedRuleProperty::Description(value) => after.description == *value,
                    OwnedRuleProperty::Disable(value) => after.disabled == *value,
                    OwnedRuleProperty::Schedule(value) => after.schedule == *value,
                    OwnedRuleProperty::Order(_) => true,
                }
        })
}
