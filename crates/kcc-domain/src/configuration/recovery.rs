//! Outcome precedence after a recovery timer has successfully armed.

/// A failed bracket, including whether cleanup left recovery armed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure<E> {
    /// Work error when work failed, otherwise the cleanup error.
    source: E,
    /// Whether cleanup failed or was not attempted.
    armed: bool,
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
            armed: true,
            applied: false,
        }
    }

    /// Whether recovery must still be treated as armed.
    #[inline]
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Whether the work is known to have completed successfully.
    #[inline]
    #[must_use]
    pub const fn applied(&self) -> bool {
        self.applied
    }

    /// Returns the original work or cleanup error.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> E {
        self.source
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
            armed: false,
            applied: false,
        }),
        (Ok(_value), Err(source)) => Err(Failure {
            source,
            armed: true,
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
    use super::finish;

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
}
