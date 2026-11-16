//! What the shared safety bracket refuses, and with which error: a recovery timer it did
//! not arm, a request nobody holds any more, and an audit writer that failed while the
//! bracket settled a failed arm.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use std::fs;

use kcc_app::{
    audit::AUDIT_FILE_NAME,
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_domain::{
    RouterCtx,
    configuration::{
        SafetyMode, SafetyNet,
        bracket::guarded,
        read_last_change,
        recovery::{Failure, Fate},
    },
};
use kcc_testkit::FaultInjection;
use serde_json::Value;

use crate::support::{Fixture, PROFILES, TestResult};

/// The length of the timer the operator armed before the bracket.
const OPERATOR_SECONDS: u64 = 3600;

/// Runs a bracket whose work succeeds at once, with `holds` as the request's owner.
// NOT cancel-safe: see `guarded`.
async fn bracket(
    changes: &mut ChangeSet,
    fixture: &Fixture,
    holds: bool,
) -> Result<(), Failure<WorkflowError>> {
    guarded(
        changes,
        fixture.context(),
        SafetyMode::Router,
        Permission::Write,
        move || holds,
        async |_changes: &mut ChangeSet, _router: &RouterCtx| Ok::<_, WorkflowError>(((), true)),
    )
    .await
}

/// C-03: a bracket refuses to run over a recovery timer the operator armed earlier.
///
/// The bracket neither replaces that timer with its own nor cancels it: nothing is sent,
/// the router still counts down the operator's timer, and the failure says why.
#[tokio::test]
async fn a_bracket_leaves_an_operator_timer_to_its_owner() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut operator = fixture.changes().await?;
        drop(
            SafetyNet::arm(
                &mut operator,
                fixture.context(),
                SafetyMode::Router,
                OPERATOR_SECONDS,
                SafetyNet::CONTROL_PERMISSION,
            )
            .await?,
        );
        drop(operator);
        let mut changes = fixture.changes().await?;
        let before = fixture.handle().request_count();

        let failure = bracket(&mut changes, &fixture, true)
            .await
            .err()
            .ok_or("the bracket ran over the operator's timer")?;

        assert_eq!(fixture.handle().request_count(), before, "{firmware}: sent");
        assert!(fixture.handle().recovery_armed(), "{firmware}: disarmed");
        let timer = read_last_change(fixture.context())
            .await?
            .fail_safe
            .and_then(|state| state.extra.get("timeout").and_then(Value::as_u64));
        assert_eq!(timer, Some(OPERATOR_SECONDS), "{firmware}: replaced");
        assert_eq!(failure.fate(), None, "{firmware}");
        assert_eq!(failure.outcome(), Fate::TimerInUse, "{firmware}");
        assert!(
            matches!(failure.into_source(), WorkflowError::RecoveryTimerInUse),
            "{firmware}: the dedicated error"
        );
        assert_eq!(fixture.workflow().brackets().count(), 0);
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-21: a request nobody holds any more is refused as unowned.
///
/// Not as a dead audit writer; nothing is sent.
#[tokio::test]
async fn an_unheld_request_is_refused_as_unowned() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        let before = fixture.handle().request_count();

        let failure = bracket(&mut changes, &fixture, false)
            .await
            .err()
            .ok_or("an unheld bracket ran")?;

        assert_eq!(fixture.handle().request_count(), before, "{firmware}: sent");
        assert_eq!(failure.outcome(), Fate::NotApplied, "{firmware}");
        assert!(
            matches!(failure.into_source(), WorkflowError::Unowned),
            "{firmware}: the unowned error"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-21: an audit writer failure after a failed arm is the bracket's failure.
///
/// It is not dropped; the accepted disarm still decides that nothing is armed.
#[tokio::test]
async fn an_audit_failure_after_a_failed_arm_is_reported() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().fail_parse_matching("fail-safe timer reboot", 1);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut changes = fixture.changes().await?;
        // The backup is taken now, while the audit file still verifies.
        changes.prepare(Permission::Write).await?;
        // The next append (the disarm's entry) finds a file that no longer verifies.
        fs::write(fixture.state_dir().join(AUDIT_FILE_NAME), b"not an entry\n")?;

        let failure = bracket(&mut changes, &fixture, true)
            .await
            .err()
            .ok_or("the bracket ran after a refused arm")?;

        assert!(!fixture.handle().recovery_armed(), "{firmware}: armed");
        assert_eq!(failure.outcome(), Fate::NotApplied, "{firmware}");
        assert!(
            matches!(failure.into_source(), WorkflowError::Audit(_)),
            "{firmware}: the audit writer's failure"
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
