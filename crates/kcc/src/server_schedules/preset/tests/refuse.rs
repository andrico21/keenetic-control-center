//! Presets a schedule may not run, refused before anything is sent, and the pure
//! decisions of the action.

use kcc_app::schedules::{
    ledger::RunOutcome,
    model::{PauseReason, ScheduleState},
    store::SchedulesDocument,
};
use kcc_domain::configuration::LastChangeState;
use kcc_migrate::apply::ApplyError;
use kcc_testkit::model::{Firmware, Model, Profile};

use super::{Bench, FIRST, OFFICE, Setup, admin};
use crate::server_schedules::{
    actions::ActionResult,
    preset::{
        PresetRefusal, Target, eligible,
        finish::{recovered, unprepared},
    },
    run::Report,
    tests::rig::{ROUTER, TestResult},
};

/// Todo 14: a management line is refused at creation and skipped at run time.
///
/// Both answer `management_lines` before any write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_management_line_is_refused_without_a_write() -> TestResult {
    let bench = Bench::start(Setup::default()).await?;
    let plain = format!("user operator\n password plain plain-{}\n", 7_u8);
    bench.capture("router-users", &plain)?;
    bench.schedule(false)?;

    let created = eligible(
        &bench.actions,
        &admin(),
        Target::new(ROUTER, "night", false),
    )
    .await;
    let report = bench.run().await?;

    assert_eq!(created, Err(PresetRefusal::ManagementLines));
    assert_eq!(
        report,
        Report::Finished(RunOutcome::Skipped {
            reason: "management_lines".to_owned()
        })
    );
    assert_eq!(bench.commands(), Vec::<String>::new());
    drop(bench.reserve()?);
    Ok(())
}

/// Todo 14: an unacknowledged documentation-based firmware line is skipped.
///
/// The run is skipped `documentation_tier`, as the plan refuses it; with the
/// acknowledgement the preset is eligible and its source router is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unacknowledged_documentation_tier_is_skipped() -> TestResult {
    let bench = Bench::start(Setup {
        profile: Profile::new(Model::Kn1811, Firmware::V5_0)?,
        ..Setup::default()
    })
    .await?;
    bench.capture_office("dns-secure", &[FIRST]).await?;
    bench.schedule(false)?;

    let report = bench.run().await?;
    let acknowledged = eligible(&bench.actions, &admin(), Target::new(ROUTER, "night", true)).await;

    assert_eq!(
        report,
        Report::Finished(RunOutcome::Skipped {
            reason: "documentation_tier".to_owned()
        })
    );
    assert_eq!(acknowledged, Ok(Some(OFFICE.to_owned())));
    assert_eq!(bench.commands(), Vec::<String>::new());
    Ok(())
}

/// Todo 14: an owner outside the preset's source router pauses the schedule.
///
/// The role covers the router but not the source router: the run pauses the schedule
/// `forbidden` before the router is contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_outside_the_source_router_pauses_the_schedule() -> TestResult {
    let bench = Bench::start(Setup {
        scope: vec![ROUTER.to_owned()],
        ..Setup::default()
    })
    .await?;
    bench.capture_office("dns-secure", &[FIRST]).await?;
    bench.schedule(false)?;

    let report = bench.run().await?;

    assert_eq!(report, Report::Paused(PauseReason::Forbidden));
    let state = bench
        .state
        .read::<SchedulesDocument>()?
        .unwrap_or_default()
        .schedules
        .into_iter()
        .map(|schedule| schedule.state)
        .collect::<Vec<_>>();
    assert!(
        matches!(
            state.as_slice(),
            [ScheduleState::Paused {
                reason: PauseReason::Forbidden,
                at: _
            }]
        ),
        "{state:?}"
    );
    assert_eq!(bench.target.request_count(), 0);
    Ok(())
}

/// Todo 14: refusals fail or skip the run under their code.
///
/// A refused role or an unreadable router fails it; a preset that may not run unattended
/// skips it.
#[test]
fn refusals_fail_or_skip_under_their_code() {
    let cases = [
        (
            PresetRefusal::Forbidden,
            ActionResult::Failed {
                code: "forbidden",
                job: None,
            },
        ),
        (
            PresetRefusal::Router,
            ActionResult::Failed {
                code: "router",
                job: None,
            },
        ),
        (
            PresetRefusal::Unavailable,
            ActionResult::Skipped {
                reason: "preset_unavailable",
                job: None,
            },
        ),
        (
            PresetRefusal::Firmware,
            ActionResult::Skipped {
                reason: "firmware",
                job: None,
            },
        ),
        (
            PresetRefusal::DocumentationTier,
            ActionResult::Skipped {
                reason: "documentation_tier",
                job: None,
            },
        ),
        (
            PresetRefusal::NotReady,
            ActionResult::Skipped {
                reason: "not_ready",
                job: None,
            },
        ),
        (
            PresetRefusal::ManagementLines,
            ActionResult::Skipped {
                reason: "management_lines",
                job: None,
            },
        ),
        (
            PresetRefusal::WireGuardKey,
            ActionResult::Skipped {
                reason: "wireguard_key",
                job: None,
            },
        ),
    ];
    for (refusal, expected) in cases {
        assert_eq!(refusal.result(), expected, "{refusal:?}");
    }
}

/// Todo 14: failures name what the router was left with.
///
/// A failed preparation says the fail-safe timer may be armed only when its arming went
/// unconfirmed; a failed finish is restored only when the router answers that nothing is
/// unsaved.
#[test]
fn failures_name_what_the_router_was_left_with() {
    assert_eq!(
        unprepared(ApplyError::ArmUnconfirmed),
        "preset_failed_armed"
    );
    assert_eq!(unprepared(ApplyError::Workflow), "preset_failed");
    let mut saved = LastChangeState::default();
    saved.unsaved = Some(false);
    let mut changed = LastChangeState::default();
    changed.unsaved = Some(true);
    assert_eq!(recovered(Some(&saved)), "preset_restored");
    assert_eq!(recovered(Some(&changed)), "preset_state_unknown");
    assert_eq!(
        recovered(Some(&LastChangeState::default())),
        "preset_state_unknown"
    );
    assert_eq!(recovered(None), "preset_state_unknown");
}
