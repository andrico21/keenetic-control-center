//! Completion facts derived from the workflow's own item validations and the ordered
//! batch responses.

use kcc_catalog::ValidatedRequest;
use serde_json::{Value, json};

/// The successful subset and value-free refusal counts.
pub(super) struct Completion {
    /// Number of successfully answered items, including reads.
    pub succeeded: usize,
    /// Number of successful items containing changes.
    pub applied_changes: usize,
    /// Number of successful change items that contain management operations.
    pub applied_management_changes: usize,
    /// Number of router-refused items.
    pub failed: usize,
    /// Successful ordinary commands require an explicit save.
    pub unsaved: bool,
    /// Every successful item persists immediately, and at least one succeeded.
    pub persists_immediately: bool,
    /// Persisted paths from successful items only.
    pub persisted_paths: Vec<String>,
}

impl Completion {
    /// The audit vocabulary distinguishes total refusal, partial and complete application.
    pub(super) const fn outcome(&self) -> &'static str {
        if self.applied_changes == 0 {
            "failed"
        } else if self.failed != 0 {
            if self.persists_immediately {
                "partially_applied_persisted"
            } else {
                "partially_applied_unsaved"
            }
        } else {
            super::applied_outcome(self.persists_immediately)
        }
    }

    /// The audit parameters of a batch the router refused part of: counts, never values.
    pub(super) fn refusal_params(&self) -> Value {
        json!({
            "error": "router_rejected",
            "succeeded": self.succeeded,
            "failed": self.failed,
        })
    }
}

/// Each item paired with whether the router accepted it, in order; refused items
/// contribute no persistence facts.
pub(super) fn completion<'item, I>(answered: I) -> Completion
where
    I: IntoIterator<Item = (&'item ValidatedRequest, bool)>,
{
    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    let mut applied_changes = 0_usize;
    let mut applied_management_changes = 0_usize;
    let mut ordinary = false;
    let mut persisted_paths = Vec::new();
    for (item, accepted) in answered {
        if !accepted {
            failed = failed.saturating_add(1);
            continue;
        }
        succeeded = succeeded.saturating_add(1);
        if item.ordinary_paths.is_empty() && item.persisted_paths.is_empty() {
            continue;
        }
        applied_changes = applied_changes.saturating_add(1);
        if item.contains_management() {
            applied_management_changes = applied_management_changes.saturating_add(1);
        }
        ordinary |= !item.ordinary_paths.is_empty();
        persisted_paths.extend(item.persisted_paths.iter().cloned());
    }
    Completion {
        succeeded,
        applied_changes,
        applied_management_changes,
        failed,
        unsaved: ordinary,
        persists_immediately: applied_changes != 0 && !ordinary,
        persisted_paths,
    }
}

/// The audit target: each item's leaf command paths, or its validated path when it changes
/// nothing.
pub(super) fn target(items: &[ValidatedRequest]) -> String {
    items
        .iter()
        .map(|item| {
            if item.ordinary_paths.is_empty() && item.persisted_paths.is_empty() {
                item.path.clone()
            } else {
                item.ordinary_paths
                    .iter()
                    .chain(&item.persisted_paths)
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
