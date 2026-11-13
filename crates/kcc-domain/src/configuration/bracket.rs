//! The shared safety bracket: arm a router's recovery timer, do the work, disarm, report.
//!
//! [`guarded`] is the one bracket every surface runs a management change through. It keeps
//! these invariants:
//!
//! - **Nothing is armed for a refused bracket.** A dead audit writer and a request the
//!   caller can no longer hold (`hold` returns false) are refused before anything is sent
//!   to the router.
//! - **Every arm has an owner.** Once the arm is sent, the bracket returns only after a
//!   disarm was sent: after a failed arm, and after the work, whatever the work returned.
//!   A failure whose disarm was refused reports the timer as armed. Only a dropped future
//!   or a panicking work escapes this; then the router's own timer restores its saved
//!   configuration, as it is meant to when kcc loses the router. Callers keep the future
//!   alive (the Web holds its request first).
//! - **The count balances.** The bracket enters the process-wide count
//!   ([`kcc_app::brackets::Brackets`]) right before the arm and leaves it when it ends,
//!   on every return path, on unwind and when dropped, so that a server waits for every
//!   open bracket before it exits and never for a closed one.
//! - **A failure never reads as armed when the timer is off, nor as off when it may be
//!   armed.** [`recovery::Failure::fate`] is `None` only when no arm was sent or a disarm
//!   was accepted after it; [`ArmedFate::NotSent`] when the arm itself failed and so did
//!   its disarm; [`ArmedFate::Applied`] when the work reported an applied change;
//!   [`ArmedFate::Unknown`] otherwise.
//! - **One permission authorizes the whole bracket.** Arm, work and disarm are all
//!   authorized by the permission of the change the timer protects, so a role that may
//!   make the change may also close its bracket.
//! - **No receipt holds back the disarm.** Inside the bracket the change set defers its
//!   audit receipts ([`ChangeSet::defer_audit`]): arm, work and disarm are queued for the
//!   audit writer in the order they were sent and return at once, so another process
//!   holding the audit append lock cannot delay the disarm. After the disarm the bracket
//!   waits at most [`BRACKET_AUDIT_WAIT`] for its receipts; entries still queued then are
//!   reported as pending and written later, in order. A writer that failed meanwhile is
//!   the bracket's failure (the timer's fate is still decided by the disarm), and a
//!   writer already dead when the work would start refuses the work.

use kcc_app::{
    audit::{AuditError, receipt::BRACKET_AUDIT_WAIT},
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    MANAGEMENT_SECONDS, SafetyMode, SafetyNet,
    recovery::{self, Failure},
};
use crate::RouterCtx;

/// What a failed bracket left on the router: every variant means the recovery timer may
/// still be armed and restore the saved configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArmedFate {
    /// The arm failed and so did its disarm: nothing else was sent.
    NotSent,
    /// The change was applied but the disarm failed.
    Applied,
    /// The change may or may not have been applied, and the disarm failed.
    Unknown,
    /// The configuration was saved but the disarm failed.
    Saved,
}

impl ArmedFate {
    /// The message that tells the user what happened and that the timer may be armed.
    #[inline]
    #[must_use]
    pub const fn message_key(self) -> MessageKey {
        match self {
            Self::NotSent => keys::MANAGEMENT_NOT_SENT_ARMED,
            Self::Applied => keys::MANAGEMENT_DISARM_FAILED,
            Self::Unknown => keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            Self::Saved => keys::FINISH_SAVED_ARMED,
        }
    }
}

/// Runs `work` inside the router's recovery timer of `mode`, all of it authorized by
/// `permission`, the permission of the change the timer protects.
///
/// `hold` is asked right before the arm whether the caller still owns the request (the Web
/// holds its request; other surfaces pass `|| true`). `work` returns its value and whether
/// at least one change item applied.
///
/// # Errors
///
/// A failure whose [`Failure::fate`] says whether the timer may still be armed: refused
/// before the arm (dead audit writer, request no longer held) with nothing sent; the arm's
/// error; or the work's error, the disarm's error after successful work, or the audit
/// writer's failure before it wrote the bracket's receipts.
// NOT cancel-safe: dropped after the arm is sent, the recovery timer stays armed with nobody
// to disarm or report it; callers keep the future alive until it returns.
#[inline]
pub async fn guarded<T, E, H, W>(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    mode: SafetyMode,
    permission: Permission,
    hold: H,
    work: W,
) -> Result<T, Failure<E>>
where
    E: From<WorkflowError>,
    H: FnOnce() -> bool,
    W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Result<(T, bool), E>,
{
    let refused = |error: WorkflowError| recovery::arm_failed(E::from(error), Ok::<(), E>(()));
    changes.audit_alive().map_err(refused)?;
    if !hold() {
        return Err(refused(WorkflowError::Audit(AuditError::WriterUnavailable)));
    }
    let _open = changes.enter_bracket();
    changes.defer_audit();
    if let Err(error) = SafetyNet::arm(changes, router, mode, MANAGEMENT_SECONDS, permission).await
    {
        let disarm = SafetyNet::disarm(changes, router, mode, permission).await;
        drop(changes.settle_audit(BRACKET_AUDIT_WAIT).await);
        return Err(recovery::arm_failed(
            E::from(error),
            disarm.map_err(E::from),
        ));
    }
    let worked = match changes.audit_alive() {
        Ok(()) => work(changes, router).await,
        Err(error) => Err(E::from(error)),
    };
    let disarm = SafetyNet::disarm(changes, router, mode, permission)
        .await
        .map_err(E::from);
    let applied = worked.as_ref().is_ok_and(|&(_, applied)| applied);
    let settled = changes.settle_audit(BRACKET_AUDIT_WAIT).await;
    let completed = match settled {
        Ok(()) => worked.map(|(value, _)| value),
        Err(error) => worked.and(Err(E::from(error))),
    };
    recovery::finish_applied(completed, disarm, applied)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::Permission;
    use kcc_catalog::Risk;
    use kcc_i18n::keys;

    use super::{ArmedFate, SafetyNet};

    /// A management change needs only its own permission; a destructive one adds
    /// `Destructive` once.
    #[test]
    fn required_adds_destructive_only_for_destructive_risk() {
        use Permission::{Destructive, RawRci, Write};
        for (permission, risk, expected) in [
            (Write, Risk::Management, vec![Write]),
            (RawRci, Risk::Management, vec![RawRci]),
            (Write, Risk::Destructive, vec![Write, Destructive]),
            (Destructive, Risk::Destructive, vec![Destructive]),
        ] {
            assert_eq!(SafetyNet::required(permission, risk), expected);
        }
    }

    /// Every armed fate names a message that says the timer may still be armed.
    #[test]
    fn armed_fates_name_their_messages() {
        for (fate, key) in [
            (ArmedFate::NotSent, keys::MANAGEMENT_NOT_SENT_ARMED),
            (ArmedFate::Applied, keys::MANAGEMENT_DISARM_FAILED),
            (ArmedFate::Unknown, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED),
            (ArmedFate::Saved, keys::FINISH_SAVED_ARMED),
        ] {
            assert_eq!(fate.message_key(), key);
        }
    }
}
