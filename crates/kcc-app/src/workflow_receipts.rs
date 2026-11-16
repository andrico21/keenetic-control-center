//! The audit receipts of one change set.
//!
//! A change set records the entry of every change it sends. Normally it waits for each
//! entry at most [`AUDIT_WAIT`]: a change the router applied is never reported as failed
//! only because another process holds the audit append lock; its entry stays queued and
//! is reported as pending.
//!
//! Queuing never waits ([`AuditLog::submit`]), however many entries are queued behind
//! another process's append lock. Inside a safety bracket the set defers: an entry is
//! queued and the change returns at once, so the bracket reaches its disarm without
//! waiting for any receipt. After the
//! disarm the bracket settles every deferred receipt within one bounded wait. Deferring
//! changes no order: the entries are queued in the order the changes were sent, and the
//! single writer writes them in that order (see `audit::writer`). A writer that failed
//! while the set deferred is reported when the bracket settles; the next change set is
//! refused before any router request.

use core::time::Duration;

use tokio::time::Instant;

use crate::audit::{
    AuditError, AuditEvent, AuditLog,
    receipt::{AUDIT_WAIT, AuditReceipt, Pending},
};

/// The entries of one change set that were not yet written when their change returned.
#[derive(Debug, Default)]
pub(super) struct Receipts {
    /// Whether changes return without waiting for their entries.
    deferred: bool,
    /// Entries still queued when their change returned.
    pending: Vec<Pending>,
}

impl Receipts {
    /// Queues `event` on `audit` and waits for it unless deferring: written, or pending.
    ///
    /// # Errors
    ///
    /// Returns a validation error, or a writer failure when not deferring; a deferred
    /// writer failure is reported by [`Self::settle`].
    // NOT cancel-safe: once queued, the entry is written even if the change set stops
    // waiting for it.
    pub(super) async fn record(
        &mut self,
        audit: &AuditLog,
        event: AuditEvent,
    ) -> Result<AuditReceipt, AuditError> {
        let queued = match audit.submit(event) {
            Err(AuditError::WriterUnavailable) if self.deferred => Pending::lost(),
            submitted => submitted?,
        };
        let receipt = if self.deferred {
            AuditReceipt::Pending(queued)
        } else {
            queued.settle(AUDIT_WAIT).await?
        };
        if let AuditReceipt::Pending(pending) = &receipt {
            self.pending.push(pending.clone());
        }
        Ok(receipt)
    }

    /// Makes later changes return without waiting for their entries.
    pub(super) const fn defer(&mut self) {
        self.deferred = true;
    }

    /// Stops deferring and waits at most `limit` for every entry still queued.
    ///
    /// # Errors
    ///
    /// [`AuditError::WriterUnavailable`] when the writer failed before writing one of
    /// them; entries still queued at the deadline are no error.
    // cancel-safe: waiting only observes the writer's progress.
    pub(super) async fn settle(&mut self, limit: Duration) -> Result<(), AuditError> {
        self.deferred = false;
        let deadline = Instant::now().checked_add(limit);
        for pending in &mut self.pending {
            let waited = match deadline {
                Some(at) => pending.wait_until(at).await,
                None => pending.wait(limit).await,
            };
            match waited {
                Ok(_) | Err(AuditError::Pending) => {}
                Err(error) => return Err(error),
            }
        }
        self.pending.retain(Pending::is_pending);
        Ok(())
    }

    /// The handles of the entries that were still queued when their change returned.
    pub(super) fn queued(&self) -> Vec<Pending> {
        self.pending.clone()
    }

    /// Whether an entry of the set is still queued.
    pub(super) fn any_pending(&self) -> bool {
        self.pending.iter().any(Pending::is_pending)
    }
}
