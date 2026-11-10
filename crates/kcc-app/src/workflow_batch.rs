//! Completion facts derived from ordered successful batch responses.

use kcc_rci::{RciError, RciResponse};

use super::BatchItem;

/// The successful subset and value-free refusal counts.
pub(super) struct Completion {
    /// Number of successfully applied items.
    pub succeeded: usize,
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
        if self.succeeded == 0 {
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
}

/// Aligns requests and responses by index; failed items contribute no persistence facts.
pub(super) fn completion(
    items: &[BatchItem],
    responses: &[Result<RciResponse, RciError>],
) -> Completion {
    let mut succeeded = 0_usize;
    let mut ordinary = false;
    let mut persisted_paths = Vec::new();
    for (item, response) in items.iter().zip(responses) {
        if response.is_ok() {
            succeeded = succeeded.saturating_add(1);
            ordinary |= !item.validated.persists_immediately;
            persisted_paths.extend(item.validated.persisted_paths.iter().cloned());
        }
    }
    Completion {
        succeeded,
        failed: responses.len().saturating_sub(succeeded),
        unsaved: ordinary,
        persists_immediately: succeeded != 0 && !ordinary,
        persisted_paths,
    }
}
