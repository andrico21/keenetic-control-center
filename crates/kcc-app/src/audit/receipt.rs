//! Bounded waits for audit entries that stay queued until they are written.
//!
//! A caller hands its entry to the writer first ([`super::AuditLog::submit`]) and only
//! then waits, at most for its own limit, for the writer's answer. When the limit passes
//! the entry is not given up: it stays queued and the writer writes it once the
//! cross-process append lock is free. The caller holds a [`Pending`] handle that tells,
//! at any later time, whether the entry was written meanwhile.
//!
//! - **An entry is never dropped for a busy lock.** Only a fatal writer failure, or the
//!   process ending first, loses a queued entry; then its handle reports the writer as
//!   unavailable instead of pending.
//! - **Waiting changes nothing.** A wait that times out or is cancelled leaves the entry
//!   where it is in the queue, so the order of the log is the order of submission.

use core::time::Duration;

use tokio::{
    sync::watch::{self, Ref, error::RecvError},
    time::{Instant, error::Elapsed, timeout, timeout_at},
};

use super::{AuditEntry, AuditError};

/// Longest an audited action waits for its entry before it reports it as pending.
pub const AUDIT_WAIT: Duration = Duration::from_secs(30);
/// Longest a safety bracket waits, after its disarm, for the entries of its changes.
pub const BRACKET_AUDIT_WAIT: Duration = Duration::from_secs(20);
/// Longest a Web sign-in waits for its entry before it signs the user in anyway.
pub const LOGIN_AUDIT_WAIT: Duration = Duration::from_secs(5);
/// Longest a server's exit waits for the writer to write the entries still queued.
pub const AUDIT_FLUSH_WAIT: Duration = Duration::from_secs(5);

/// What the writer did with one queued entry.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "one reply lives per queued entry, in its own channel; boxing the entry buys nothing"
)]
pub(super) enum Reply {
    /// Still queued.
    Queued,
    /// Written with its sequence number and chain hash.
    Written(AuditEntry),
    /// Not written: the writer failed and stopped.
    Failed,
}

/// The handle of one queued entry: whether, and as what, it was written.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Pending {
    /// The writer's answer.
    reply: watch::Receiver<Reply>,
}

impl Pending {
    /// The handle of an entry whose answer arrives on `reply`.
    pub(super) const fn new(reply: watch::Receiver<Reply>) -> Self {
        Self { reply }
    }

    /// The handle of an entry that could not be queued because the writer is gone.
    pub(crate) fn lost() -> Self {
        let (_writer, reply) = watch::channel(Reply::Failed);
        Self { reply }
    }

    /// Whether the entry is still queued: neither written nor lost with the writer.
    #[inline]
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(*self.reply.borrow(), Reply::Queued) && self.reply.has_changed().is_ok()
    }

    /// Waits at most `limit` for the entry to be written.
    ///
    /// # Errors
    ///
    /// [`AuditError::Pending`] when the limit passes first (the entry stays queued), or
    /// [`AuditError::WriterUnavailable`] when the writer failed before writing it.
    // cancel-safe: waiting only observes the writer's answer; the entry stays queued.
    #[inline]
    pub async fn wait(&mut self, limit: Duration) -> Result<AuditEntry, AuditError> {
        let answered = self.reply.wait_for(|reply| !matches!(reply, Reply::Queued));
        written(timeout(limit, answered).await)
    }

    /// Waits until `deadline` for the entry to be written.
    ///
    /// # Errors
    ///
    /// As [`Self::wait`].
    // cancel-safe: waiting only observes the writer's answer; the entry stays queued.
    #[inline]
    pub async fn wait_until(&mut self, deadline: Instant) -> Result<AuditEntry, AuditError> {
        let answered = self.reply.wait_for(|reply| !matches!(reply, Reply::Queued));
        written(timeout_at(deadline, answered).await)
    }

    /// Waits at most `limit` for the entry: written, or still pending with this handle.
    ///
    /// # Errors
    ///
    /// [`AuditError::WriterUnavailable`] when the writer failed before writing it.
    // cancel-safe: waiting only observes the writer's answer; the entry stays queued.
    #[inline]
    pub async fn settle(mut self, limit: Duration) -> Result<AuditReceipt, AuditError> {
        match self.wait(limit).await {
            Ok(entry) => Ok(AuditReceipt::Written(entry)),
            Err(AuditError::Pending) => Ok(AuditReceipt::Pending(self)),
            Err(error) => Err(error),
        }
    }
}

/// The entry of a bounded wait for the writer's answer.
///
/// # Errors
///
/// [`AuditError::Pending`] when the wait ended first, else
/// [`AuditError::WriterUnavailable`] when the writer did not write the entry.
fn written(
    answered: Result<Result<Ref<'_, Reply>, RecvError>, Elapsed>,
) -> Result<AuditEntry, AuditError> {
    match answered {
        Err(_elapsed) => Err(AuditError::Pending),
        Ok(Err(_closed)) => Err(AuditError::WriterUnavailable),
        Ok(Ok(reply)) => match &*reply {
            Reply::Written(entry) => Ok(entry.clone()),
            Reply::Queued | Reply::Failed => Err(AuditError::WriterUnavailable),
        },
    }
}

/// What became of an audited change's entry when the change returned.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::large_enum_variant,
    reason = "one receipt per applied change, returned once; the written entry is kept as is"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Receipt next to the change results carrying it"
)]
pub enum AuditReceipt {
    /// The entry was written.
    Written(AuditEntry),
    /// The entry was still queued; it is written once the append lock is free.
    Pending(Pending),
}

impl AuditReceipt {
    /// Whether the entry is still queued now.
    #[inline]
    #[must_use]
    pub fn is_pending(&self) -> bool {
        match self {
            Self::Written(_entry) => false,
            Self::Pending(pending) => pending.is_pending(),
        }
    }
}
