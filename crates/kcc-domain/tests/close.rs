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
/// `(applied, armed)` failure when the router refuses `save`.
type Row = (
    Close,
    SafetyMode,
    &'static [&'static str],
    Result<(bool, bool), (bool, bool)>,
);

const ROWS: [Row; 7] = [
    (
        Close::KeepUnsaved,
        SafetyMode::Router,
        &["no system configuration fail-safe timer"],
        Ok((false, false)),
    ),
    (
        Close::KeepUnsaved,
        SafetyMode::ScheduledReboot,
        &["no system reboot"],
        Ok((false, false)),
    ),
    (
        Close::Save,
        SafetyMode::Router,
        &[
            "system configuration fail-safe commit",
            "system configuration save",
        ],
        Ok((true, false)),
    ),
    (
        Close::Save,
        SafetyMode::ScheduledReboot,
        &["system configuration save", "no system reboot"],
        Ok((true, false)),
    ),
    (
        Close::Rollback,
        SafetyMode::Router,
        &["system configuration fail-safe rollback"],
        Ok((false, false)),
    ),
    (
        Close::Rollback,
        SafetyMode::ScheduledReboot,
        &["system reboot"],
        Ok((false, true)),
    ),
    (
        Close::Save,
        SafetyMode::Router,
        &[
            "system configuration fail-safe commit",
            "system configuration save",
        ],
        Err((true, false)),
    ),
];

#[tokio::test]
async fn close_sends_the_step_of_the_armed_mechanism() -> TestResult {
    for firmware in PROFILES {
        for (step, mode, sent, expected) in ROWS {
            let faults = if expected.is_err() {
                FaultInjection::default().fail_parse_matching("system configuration save", 1)
            } else {
                FaultInjection::default()
            };
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
            let _: ChangeResult = changes.apply(system::change_request(&plan)?).await?;
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
