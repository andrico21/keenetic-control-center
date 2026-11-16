//! The recovery timer's disarm and keep-alive are sent whatever the change set's write
//! preflight would refuse, and a refused arm sends and arms nothing.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeResult, ChangeSet, WorkflowError},
};
use kcc_domain::{
    RouterCtx,
    configuration::{
        SafetyMode, SafetyNet,
        bracket::{ArmedFate, guarded},
        recovery::Fate,
    },
    system,
};
use kcc_i18n::keys;
use kcc_testkit::{FaultInjection, model::Firmware};

use crate::support::{Fixture, PROFILES, TestResult};

/// The line another RCI client sends meanwhile; it changes the running configuration.
const FOREIGN: &str = "ip name-server 192.0.2.53";

/// The parser lines the router saw after `before` requests.
fn commands_after(fixture: &Fixture, before: usize) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .into_iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// The arm and disarm lines of `mode`.
const fn lines(mode: SafetyMode) -> [&'static str; 2] {
    match mode {
        SafetyMode::Router => [
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        ],
        SafetyMode::ScheduledReboot => ["system reboot 300", "no system reboot"],
        _ => ["unknown arm", "unknown disarm"],
    }
}

/// Changes the router through the fixture's own RCI session, which is not the change
/// set's: the router reports the same agent as for kcc's writes.
// NOT cancel-safe: the sent line applies on the router.
async fn change_by_another_client(router: &RouterCtx) -> Result<(), WorkflowError> {
    drop(router.client.parse(FOREIGN).await?);
    Ok(())
}

/// C-02: work refused locally after the arm (another client changed the router, so the
/// work's own write is refused as a conflict) still sends the disarm.
///
/// An accepted disarm leaves nothing armed and keeps the work's error; a disarm the
/// router refuses reads as armed.
#[tokio::test]
async fn a_locally_refused_work_still_sends_the_disarm() -> TestResult {
    for firmware in PROFILES {
        for system_mode in ["router", "extender"] {
            for disarm_refused in [false, true] {
                let faults = if disarm_refused {
                    FaultInjection::default().fail_parse_matching("no system", 1)
                } else {
                    FaultInjection::default()
                };
                let fixture = Fixture::spawn_mode(firmware, system_mode, faults).await?;
                let mut changes = fixture.changes().await?;
                let mode = SafetyMode::for_change(&changes)?;
                let plan = system::plan_description(fixture.context(), "bracketed")?;
                let request = system::change_request(&plan)?;
                let before = fixture.handle().request_log().len();

                let outcome = guarded(
                    &mut changes,
                    fixture.context(),
                    mode,
                    Permission::Write,
                    || true,
                    async move |set: &mut ChangeSet, router: &RouterCtx| {
                        change_by_another_client(router).await?;
                        let _applied: ChangeResult = set.apply(request).await?;
                        Ok::<_, WorkflowError>(((), true))
                    },
                )
                .await;

                let label = format!("{firmware} {system_mode} disarm refused {disarm_refused}");
                let failure = outcome.err().ok_or_else(|| format!("{label}: succeeded"))?;
                let [arm, disarm] = lines(mode);
                assert_eq!(
                    commands_after(&fixture, before),
                    [arm, FOREIGN, disarm],
                    "{label}"
                );
                if disarm_refused {
                    assert_eq!(failure.fate(), Some(ArmedFate::Unknown), "{label}");
                } else {
                    assert_eq!(failure.fate(), None, "{label}");
                    assert!(!fixture.handle().recovery_armed(), "{label}: fake armed");
                    assert!(
                        matches!(failure.into_source(), WorkflowError::Conflict { agent: _ }),
                        "{label}: the work's error"
                    );
                }
                drop(changes);
                fixture.shutdown().await?;
            }
        }
    }
    Ok(())
}

/// C-02: an arm refused by the change set's preflight (another client changed the router
/// since the set began) sends nothing, and the failure says nothing is armed.
#[tokio::test]
async fn an_arm_refused_before_sending_reports_nothing_armed() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        change_by_another_client(fixture.context()).await?;
        let before = fixture.handle().request_log().len();

        let outcome = guarded(
            &mut changes,
            fixture.context(),
            SafetyMode::Router,
            Permission::Write,
            || true,
            async |_set: &mut ChangeSet, _router: &RouterCtx| Ok::<_, WorkflowError>(((), true)),
        )
        .await;

        let failure = outcome.err().ok_or("the refused bracket succeeded")?;
        assert_eq!(failure.fate(), None, "{firmware}");
        assert_eq!(failure.outcome(), Fate::NotApplied, "{firmware}");
        assert_eq!(failure.message_key(), Some(keys::MANAGEMENT_NOT_APPLIED));
        assert_eq!(commands_after(&fixture, before), Vec::<String>::new());
        assert!(!fixture.handle().recovery_armed(), "{firmware}: fake armed");
        assert_eq!(fixture.workflow().brackets().count(), 0, "{firmware}");
        assert!(matches!(
            failure.into_source(),
            WorkflowError::Conflict { agent: _ }
        ));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-02: the keep-alive and the disarm are sent after another client changed the router,
/// and that change still refuses the set's later save.
#[tokio::test]
async fn keep_alive_and_disarm_skip_the_conflict_check() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let mut changes = fixture.changes().await?;
    let router = fixture.context();
    drop(
        SafetyNet::arm(
            &mut changes,
            router,
            SafetyMode::Router,
            300,
            Permission::Write,
        )
        .await?,
    );
    change_by_another_client(router).await?;
    let before = fixture.handle().request_log().len();

    drop(SafetyNet::keep_alive(&mut changes, router, Permission::Write).await?);
    drop(SafetyNet::disarm(&mut changes, router, SafetyMode::Router, Permission::Write).await?);

    assert_eq!(
        commands_after(&fixture, before),
        [
            "system configuration fail-safe keep-alive",
            "no system configuration fail-safe timer",
        ]
    );
    assert!(!fixture.handle().recovery_armed());
    assert!(
        changes
            .save()
            .await
            .is_err_and(|error| matches!(error, WorkflowError::Conflict { agent: _ }))
    );
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}
