//! The cleanup guard of the SSH suite: once the bootstrap was attempted, the revoke runs
//! whatever the steps did, and a failed revoke names the manual step the owner must take.

use core::{cell::Cell, error::Error, fmt};
use std::path::Path;

use super::TestResult;

/// Why the guarded steps did not pass.
#[derive(Debug)]
pub(crate) enum Cleanup {
    /// A step failed; the revoke succeeded.
    Steps(Box<dyn Error>),
    /// The revoke failed, after the steps passed (`steps` = `None`) or failed.
    Revoke {
        /// The steps' failure, if any.
        steps: Option<Box<dyn Error>>,
        /// The revoke's failure.
        revoke: Box<dyn Error>,
    },
}

/// Runs `steps`, then `revoke` whatever `steps` returned.
///
/// # Errors
/// [`Cleanup::Steps`] when only the steps failed, [`Cleanup::Revoke`] when the revoke
/// failed.
pub(crate) fn always_revoke<S, R>(steps: S, revoke: R) -> Result<(), Cleanup>
where
    S: FnOnce() -> TestResult,
    R: FnOnce() -> TestResult,
{
    let outcome = steps();
    match (outcome, revoke()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(failure), Ok(())) => Err(Cleanup::Steps(failure)),
        (earlier, Err(failure)) => Err(Cleanup::Revoke {
            steps: earlier.err(),
            revoke: failure,
        }),
    }
}

/// A failed revoke: the key line kcc added is still authorized on the router.
#[derive(Debug)]
pub(crate) struct RevokeFailed {
    /// What the owner must do, with the kept kcc home.
    pub manual: String,
}

impl fmt::Display for RevokeFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.manual)
    }
}

impl Error for RevokeFailed {}

/// The manual step after a failed revoke; `home` is the kept kcc home of the run.
pub(crate) fn manual(router: &str, home: &Path, (steps, revoke): (Option<&str>, &str)) -> String {
    format!(
        "the revoke failed ({revoke}); the steps {}. kcc's key is still authorized on the router: retry with `KCC_MASTER_KEY_FILE={} kcc --config {} --confirm-destructive {router} entware ssh revoke`, or remove the line ending in ` kcc:{router}` from /opt/etc/dropbear/authorized_keys on the router by hand. `kcc entware ssh disable` only forgets the key locally and does not remove that line.",
        steps.map_or_else(|| "passed".to_owned(), |error| format!("failed: {error}")),
        home.join("master.key").display(),
        home.join("kcc.toml").display(),
    )
}

/// Todo 19: a failing step still runs the revoke, exactly once, and reports the step.
#[test]
fn a_failing_step_still_revokes() {
    let revoked = Cell::new(0_u8);
    let outcome = always_revoke(
        || Err("package step failed".into()),
        || {
            revoked.set(revoked.get().saturating_add(1));
            Ok(())
        },
    );
    assert_eq!(revoked.get(), 1, "revoke runs once after a failing step");
    assert!(matches!(outcome, Err(Cleanup::Steps(_))), "{outcome:?}");
}

/// Todo 19: passing steps revoke once and pass.
#[test]
fn passing_steps_revoke_and_pass() {
    let revoked = Cell::new(0_u8);
    let outcome = always_revoke(
        || Ok(()),
        || {
            revoked.set(revoked.get().saturating_add(1));
            Ok(())
        },
    );
    assert_eq!(revoked.get(), 1);
    assert!(outcome.is_ok(), "{outcome:?}");
}

/// Todo 19: a failing revoke is reported as such, with or without a failed step.
#[test]
fn a_failing_revoke_is_reported_with_the_step_outcome() {
    let after_pass = always_revoke(|| Ok(()), || Err("revoke failed".into()));
    assert!(
        matches!(
            after_pass,
            Err(Cleanup::Revoke {
                steps: None,
                revoke: _
            })
        ),
        "{after_pass:?}"
    );
    let after_failure = always_revoke(|| Err("step failed".into()), || Err("revoke failed".into()));
    assert!(
        matches!(
            after_failure,
            Err(Cleanup::Revoke {
                steps: Some(_),
                revoke: _
            })
        ),
        "{after_failure:?}"
    );
}
