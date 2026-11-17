//! What step 5 asks for.
//!
//! Passwords of router users whose hashes are bound to the source's realm, consent to
//! install components first, the URL to reach the router at after management changes,
//! and acceptance of the router's agreements.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_config::config_text::flatten;
use kcc_migrate::{
    inventory::TargetInventory,
    rules::{ClassifiedItem, reason::Reason},
};

use super::{analysis::Analysis, plan::Classified, reasons::password_user, record::Record};

/// The inputs a migration needs.
pub(super) struct Needs {
    /// Users whose password must be typed, in name order.
    users: Vec<String>,
    /// Components the source's settings need, with how many settings need each.
    components: BTreeMap<String, usize>,
    /// Whether the plan changes how kcc reaches the router.
    reconnect: bool,
    /// Agreements to accept: name and text.
    agreements: Vec<(&'static str, String)>,
}

impl Needs {
    /// What `record` still needs for `analysis`, classified as `classified`.
    pub(super) fn of(analysis: &Analysis, classified: &Classified, record: &Record) -> Self {
        let kept = classified
            .items()
            .iter()
            .filter(|item| !record.excluded().contains(&item.source_index))
            .collect::<Vec<_>>();
        let mut users = kept
            .iter()
            .map(|item| password_user(item))
            .filter(|user| !user.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        users.sort();
        users.dedup();
        let target = analysis.target();
        let present = flatten(&target.running_config)
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let reconnect = kept.iter().any(|item| {
            item.reason == Reason::PasswordRealm
                || (manages(item, target)
                    && item
                        .after
                        .as_ref()
                        .is_some_and(|after| !present.contains(after)))
        });
        Self {
            users,
            components: classified
                .components(record)
                .into_iter()
                .map(|(name, items)| (name, items.len()))
                .collect(),
            reconnect,
            agreements: analysis
                .agreements()
                .iter()
                .map(|agreement| (agreement.name(), agreement.text().to_owned()))
                .collect(),
        }
    }

    /// Users whose password must be typed.
    pub(super) fn users(&self) -> &[String] {
        &self.users
    }

    /// Components the source's settings need, with how many settings need each.
    pub(super) const fn components(&self) -> &BTreeMap<String, usize> {
        &self.components
    }

    /// Whether the plan changes how kcc reaches the router.
    pub(super) const fn reconnect(&self) -> bool {
        self.reconnect
    }

    /// Agreements to accept: name and text.
    pub(super) fn agreements(&self) -> &[(&'static str, String)] {
        &self.agreements
    }

    /// Whether nothing is needed.
    pub(super) fn none(&self) -> bool {
        self.users.is_empty()
            && self.components.is_empty()
            && !self.reconnect
            && self.agreements.is_empty()
    }
}

/// Whether `item` changes how kcc reaches the router: the web server's port or TLS, or
/// the address or security level of an interface that may carry the management connection.
fn manages(item: &ClassifiedItem, target: &TargetInventory) -> bool {
    let line = item.after.as_deref().unwrap_or(&item.before);
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["ip", "http", "port" | "ssl", ..] => true,
        ["interface", name, "ip", "address" | "security-level", ..]
        | ["interface", name, "security-level", ..] => target.may_carry_management(name),
        _ => false,
    }
}
