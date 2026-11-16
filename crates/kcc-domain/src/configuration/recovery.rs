//! Outcome precedence of a recovery bracket: what a failure says about the recovery timer.

use kcc_i18n::{bundle::MessageKey, keys};

use super::bracket::ArmedFate;

/// What a failed bracket left on the router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fate {
    /// The recovery timer may still be armed, as the armed fate says.
    Armed(ArmedFate),
    /// The arm was refused and its disarm accepted: nothing was applied and the timer is off.
    NotApplied,
    /// Something was sent and the timer is off: the original error tells what happened.
    Settled,
}

/// A failed bracket, including whether the recovery timer may still be armed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure<E> {
    /// Work error when work failed, otherwise the arm or cleanup error.
    source: E,
    /// What may still be armed, and after what; `None` when recovery is known to be off.
    fate: Option<ArmedFate>,
    /// Whether anything was sent after the arm; false only when the arm itself failed.
    sent: bool,
    /// Whether work completed successfully before cleanup failed.
    applied: bool,
}

impl<E> Failure<E> {
    /// Records an early failure after arming, before cleanup was attempted.
    #[inline]
    #[must_use]
    pub const fn armed(source: E) -> Self {
        Self {
            source,
            fate: Some(ArmedFate::Unknown),
            sent: true,
            applied: false,
        }
    }

    /// Records a failure after the work was applied and recovery was resolved.
    #[inline]
    #[must_use]
    pub(crate) const fn committed(source: E) -> Self {
        Self {
            source,
            fate: None,
            sent: true,
            applied: true,
        }
    }

    /// Records a disarm that failed after the configuration was saved.
    #[inline]
    #[must_use]
    pub(crate) const fn saved(source: E) -> Self {
        Self {
            source,
            fate: Some(ArmedFate::Saved),
            sent: true,
            applied: true,
        }
    }

    /// Whether recovery must still be treated as armed.
    #[inline]
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.fate.is_some()
    }

    /// Whether the work is known to have completed successfully.
    #[inline]
    #[must_use]
    pub const fn applied(&self) -> bool {
        self.applied
    }

    /// What may still be armed: `None` when recovery is known to be off; otherwise
    /// [`ArmedFate::NotSent`] when the arm itself failed, [`ArmedFate::Saved`] when the
    /// configuration was saved, [`ArmedFate::Applied`] when the work applied, and
    /// [`ArmedFate::Unknown`] otherwise.
    #[inline]
    #[must_use]
    pub const fn fate(&self) -> Option<ArmedFate> {
        self.fate
    }

    /// What the failed bracket left on the router.
    #[inline]
    #[must_use]
    pub const fn outcome(&self) -> Fate {
        match (self.fate, self.sent) {
            (Some(fate), _) => Fate::Armed(fate),
            (None, false) => Fate::NotApplied,
            (None, true) => Fate::Settled,
        }
    }

    /// The message that states this failure's outcome, when the failure itself decides it:
    /// the armed fate's message; `management-not-applied` when the arm failed and the timer
    /// is off. `None` when something was sent and recovery is off: the original error (or
    /// the caller's own outcome) tells what happened.
    #[inline]
    #[must_use]
    pub const fn message_key(&self) -> Option<MessageKey> {
        match self.outcome() {
            Fate::Armed(fate) => Some(fate.message_key()),
            Fate::NotApplied => Some(keys::MANAGEMENT_NOT_APPLIED),
            Fate::Settled => None,
        }
    }

    /// Returns the original work or cleanup error.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> E {
        self.source
    }
}

/// Records a bracket refused before its arm was sent: nothing was sent, nothing is armed.
#[inline]
#[must_use]
pub const fn refused<E>(source: E) -> Failure<E> {
    Failure {
        source,
        fate: None,
        sent: false,
        applied: false,
    }
}

/// Records an arm that failed after its preflight, from the disarm sent after it: recovery
/// may still be armed,
/// with nothing sent after the arm, only when that disarm failed too.
///
/// The arm's error is kept; the cleanup error is dropped.
#[inline]
#[must_use]
pub fn arm_failed<D, E>(source: E, disarm: Result<D, E>) -> Failure<E> {
    Failure {
        source,
        fate: match disarm {
            Ok(_disarmed) => None,
            Err(_cleanup) => Some(ArmedFate::NotSent),
        },
        sent: false,
        applied: false,
    }
}

/// Combines work and cleanup without losing either the work outcome or armed state.
///
/// # Errors
/// Returns the work error after successful cleanup, or an armed failure otherwise.
#[inline]
pub fn finish<T, D, E>(work: Result<T, E>, disarm: Result<D, E>) -> Result<T, Failure<E>> {
    let applied = work.is_ok();
    finish_applied(work, disarm, applied)
}

/// Combines cleanup with the completion's known application fact.
///
/// Batch callers pass whether at least one change item succeeded, excluding reads.
/// The work result alone cannot establish that fact for a partially refused batch.
///
/// # Errors
/// Returns the work error after successful cleanup, or an armed failure otherwise.
#[inline]
pub fn finish_applied<T, D, E>(
    work: Result<T, E>,
    disarm: Result<D, E>,
    applied: bool,
) -> Result<T, Failure<E>> {
    match (work, disarm) {
        (Ok(value), Ok(_disarmed)) => Ok(value),
        (Err(source), Ok(_disarmed)) => Err(Failure {
            source,
            fate: None,
            sent: true,
            applied: false,
        }),
        (Ok(_value), Err(source)) => Err(Failure {
            source,
            fate: Some(if applied {
                ArmedFate::Applied
            } else {
                ArmedFate::Unknown
            }),
            sent: true,
            applied,
        }),
        (Err(source), Err(_cleanup)) => Err(Failure::armed(source)),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use kcc_i18n::keys;

    use super::{ArmedFate, Fate, arm_failed, finish};

    /// Cleanup success preserves work errors; cleanup failure always retains armed state.
    #[test]
    fn completion_preserves_work_and_recovery_outcomes() {
        for (work, cleanup, expected) in [
            (Ok(7_u8), Ok(()), Ok(7_u8)),
            (Err("work"), Ok(()), Err(("work", false, false))),
            (Ok(7_u8), Err("cleanup"), Err(("cleanup", true, true))),
            (Err("work"), Err("cleanup"), Err(("work", true, false))),
        ] {
            let actual = finish(work, cleanup).map_err(|error| {
                let armed = error.is_armed();
                let applied = error.applied();
                (error.into_source(), armed, applied)
            });
            assert_eq!(actual, expected);
        }
    }

    /// E-17: a failed bracket states what it left as a typed fate.
    ///
    /// A front end tells a refused arm (nothing applied, timer off) from an armed or
    /// settled one without comparing its message key.
    #[test]
    fn a_failed_bracket_states_its_fate() {
        let off = arm_failed("arm", Ok::<(), _>(()));
        assert_eq!(off.outcome(), Fate::NotApplied);
        let armed = arm_failed("arm", Err::<(), _>("disarm"));
        assert_eq!(armed.outcome(), Fate::Armed(ArmedFate::NotSent));
        let refused = finish(Err::<(), _>("work"), Ok::<(), _>(()));
        assert_eq!(
            refused.err().map(|failure| failure.outcome()),
            Some(Fate::Settled)
        );
    }

    /// A failed arm reads as armed only when its disarm failed too, and then as not sent; a
    /// failure that left the timer off never carries an armed message.
    #[test]
    fn a_failed_arm_reads_as_armed_only_when_its_disarm_failed() {
        let off = arm_failed("arm", Ok::<(), _>(()));
        assert_eq!(off.fate(), None);
        assert_eq!(off.message_key(), Some(keys::MANAGEMENT_NOT_APPLIED));
        let armed = arm_failed("arm", Err::<(), _>("disarm"));
        assert_eq!(armed.fate(), Some(ArmedFate::NotSent));
        assert_eq!(armed.message_key(), Some(keys::MANAGEMENT_NOT_SENT_ARMED));
        assert_eq!(armed.into_source(), "arm");
        let refused = finish(Err::<(), _>("work"), Ok::<(), _>(()));
        assert_eq!(
            refused.err().and_then(|failure| failure.message_key()),
            None
        );
    }
}
