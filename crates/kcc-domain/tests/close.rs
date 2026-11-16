//! The closing step of a recovery bracket, per step and recovery mechanism.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_app::workflow::ChangeResult;
use kcc_domain::{
    configuration::{
        SafetyMode, SafetyNet,
        close::{Close, close},
    },
    system,
};
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

/// Commands a step sends, in order, and its `(saved, restarting)` report, or the
/// `(applied, armed)` failure when the router refuses the line matching the row's
/// `(substring, times)` fault.
type Row = (
    Close,
    SafetyMode,
    Option<&'static str>,
    &'static [&'static str],
    Result<(bool, bool), (bool, bool)>,
);

const ROWS: [Row; 8] = [
    (
        Close::KeepUnsaved,
        SafetyMode::Router,
        None,
        &["no system configuration fail-safe timer"],
        Ok((false, false)),
    ),
    (
        Close::KeepUnsaved,
        SafetyMode::ScheduledReboot,
        None,
        &["no system reboot"],
        Ok((false, false)),
    ),
    (
        Close::Save,
        SafetyMode::Router,
        None,
        &["system configuration fail-safe commit"],
        Ok((true, false)),
    ),
    (
        Close::Save,
        SafetyMode::ScheduledReboot,
        None,
        &["system configuration save", "no system reboot"],
        Ok((true, false)),
    ),
    (
        Close::Rollback,
        SafetyMode::Router,
        None,
        &["system configuration fail-safe rollback"],
        Ok((false, false)),
    ),
    (
        Close::Rollback,
        SafetyMode::ScheduledReboot,
        None,
        &["system reboot"],
        Ok((false, true)),
    ),
    // A refused commit leaves the timer armed with nothing saved.
    (
        Close::Save,
        SafetyMode::Router,
        Some("fail-safe commit"),
        &["system configuration fail-safe commit"],
        Err((false, true)),
    ),
    // A refused keep-unsaved disarm leaves the applied change under the armed timer.
    (
        Close::KeepUnsaved,
        SafetyMode::Router,
        Some("no system configuration fail-safe timer"),
        &["no system configuration fail-safe timer"],
        Err((true, true)),
    ),
];

/// C-15: a router-mode save sends the fail-safe commit alone.
///
/// The commit already waits for the startup configuration to be saved; no second save
/// follows it.
#[tokio::test]
async fn close_sends_the_step_of_the_armed_mechanism() -> TestResult {
    for firmware in PROFILES {
        for (step, mode, refused, sent, expected) in ROWS {
            let faults = refused.map_or_else(FaultInjection::default, |line| {
                FaultInjection::default().fail_parse_matching(line, 1)
            });
            let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
            let mut changes = fixture.changes().await?;
            drop(
                SafetyNet::arm(
                    &mut changes,
                    fixture.context(),
                    mode,
                    300,
                    SafetyNet::CONTROL_PERMISSION,
                )
                .await?,
            );
            let plan = system::plan_description(fixture.context(), "closing")?;
            let _applied: ChangeResult = changes.apply(system::change_request(&plan)?).await?;
            let before = fixture.handle().request_log().len();

            let closed = close(
                &mut changes,
                fixture.context(),
                mode,
                (step, SafetyNet::CONTROL_PERMISSION),
            )
            .await;

            let commands = fixture
                .handle()
                .request_log()
                .into_iter()
                .skip(before)
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            assert_eq!(commands, sent, "{firmware} {step:?} {mode:?}");
            let actual = closed
                .map(|done| (done.saved, done.restarting))
                .map_err(|failure| (failure.applied(), failure.is_armed()));
            assert_eq!(actual, expected, "{firmware} {step:?} {mode:?}");
            drop(changes);
            fixture.shutdown().await?;
        }
    }
    Ok(())
}
