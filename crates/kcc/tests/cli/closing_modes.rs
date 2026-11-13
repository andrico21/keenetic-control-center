//! Each closing step sends the router command of the target's recovery mode.

use core::error::Error;

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FaultInjection, RequestRecord};

use super::{
    closing::{run_id, target},
    support::{Run, TestResult},
};

/// Where a closing step runs from.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// `kcc config failsafe <step>`.
    Config,
    /// `kcc preset finish <run> <step>`.
    Preset,
    /// `kcc migrate finish <step>`.
    Migrate,
}

/// One closing step: mode, path, step, commands sent in order, commands never sent.
type Row = (
    &'static str,
    Path,
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

const FAIL_SAFE_ROLLBACK: &str = "system configuration fail-safe rollback";

const ROWS: [Row; 8] = [
    (
        "extender",
        Path::Config,
        "rollback",
        &["system reboot"],
        &[FAIL_SAFE_ROLLBACK],
    ),
    (
        "extender",
        Path::Preset,
        "rollback",
        &["system reboot"],
        &[FAIL_SAFE_ROLLBACK],
    ),
    (
        "extender",
        Path::Migrate,
        "rollback",
        &["system reboot"],
        &[FAIL_SAFE_ROLLBACK],
    ),
    (
        "router",
        Path::Config,
        "rollback",
        &[FAIL_SAFE_ROLLBACK],
        &["system reboot"],
    ),
    (
        "router",
        Path::Preset,
        "rollback",
        &[FAIL_SAFE_ROLLBACK],
        &["system reboot"],
    ),
    (
        "router",
        Path::Migrate,
        "rollback",
        &[FAIL_SAFE_ROLLBACK],
        &["system reboot"],
    ),
    (
        "router",
        Path::Config,
        "commit",
        &[
            "system configuration fail-safe commit",
            "system configuration save",
        ],
        &["system reboot"],
    ),
    (
        "extender",
        Path::Preset,
        "keep-unsaved",
        &["no system reboot"],
        &[FAIL_SAFE_ROLLBACK, "system configuration save"],
    ),
];

/// Rollback reboots in scheduled-reboot mode and uses the native rollback in router mode;
/// a router-mode commit also saves; keep-unsaved cancels the scheduled reboot.
// NOT cancel-safe: arms, changes and closes each fixture router.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_steps_send_the_mode_command() -> TestResult {
    let mut failures = Vec::new();
    for (mode, path, step, sent, never) in ROWS {
        let (env, handle) = target(mode, FaultInjection::default()).await?;
        let arm = env.kcc(&[
            "--confirm-destructive",
            "target",
            "config",
            "failsafe",
            "arm",
        ])?;
        assert_eq!(arm.code, 0_i32, "{arm:?}");
        let changed = env.kcc(&["system", "set-description", "closing-mode"])?;
        assert_eq!(changed.code, 0_i32, "{changed:?}");
        let job = run_id(&env).await?;
        let before = handle.request_log().len();

        let run = match path {
            Path::Config => env.kcc(&[
                "--confirm-destructive",
                "target",
                "config",
                "failsafe",
                step,
            ]),
            Path::Preset => env.kcc(&[
                "--yes",
                "--confirm-destructive",
                "target",
                "preset",
                "finish",
                &job,
                step,
            ]),
            Path::Migrate => {
                env.kcc(&["--confirm-destructive", "target", "migrate", "finish", step])
            }
        }?;

        let commands = handle
            .request_log()
            .into_iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .collect::<Vec<_>>();
        let mut rest = commands.iter();
        let in_order = sent
            .iter()
            .all(|expected| rest.any(|command| command == expected));
        let forbidden = commands
            .iter()
            .any(|command| never.contains(&command.as_str()));
        if run.code != 0_i32 || !in_order || forbidden {
            failures.push(format!("{mode} {path:?} {step}: {commands:?}; {run:?}"));
        }
        handle.shutdown().await?;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// Runs an explicit scheduled rollback on an extender that answers `fail_after` requests;
/// returns the run, the reboots the router received and the requests it answered.
// NOT cancel-safe: arms, changes and reboots the fixture router.
async fn explicit_extender_rollback(
    fail_after: Option<u64>,
) -> Result<(Run, Vec<RequestRecord>), Box<dyn Error>> {
    let faults = fail_after.map_or_else(FaultInjection::default, |count| {
        FaultInjection::default().fail_after_requests(count)
    });
    let (env, handle) = target("extender", faults).await?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "target",
        "config",
        "failsafe",
        "arm",
    ])?;
    assert_eq!(arm.code, 0_i32, "{arm:?}");
    let changed = env.kcc(&["system", "set-description", "silent-reboot"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let run = env.kcc(&[
        "--confirm-destructive",
        "target",
        "migrate",
        "finish",
        "rollback",
    ])?;
    let log = handle.request_log();
    handle.shutdown().await?;
    Ok((run, log))
}

/// A reboot the extender accepts before going silent reports that the router is
/// restarting with its saved configuration, the same meaning as every other surface.
// NOT cancel-safe: arms, changes and reboots both fixture routers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_explicit_extender_rollback_reports_restarting() -> TestResult {
    let (baseline, baseline_log) = explicit_extender_rollback(None).await?;
    assert_eq!(baseline.code, 0_i32, "{baseline:?}");
    let reboot = baseline_log
        .iter()
        .position(|record| record.command() == Some("system reboot"))
        .and_then(|index| u64::try_from(index).ok())
        .ok_or("the baseline rollback sends no reboot")?;

    let (run, log) = explicit_extender_rollback(Some(reboot.saturating_add(1))).await?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout
            .contains(&tr(Locale::En, keys::MIGRATE_ROLLBACK_SAVED, None)),
        "{run:?}"
    );
    let reboots = log
        .iter()
        .filter(|record| record.command() == Some("system reboot"))
        .count();
    assert_eq!(reboots, 1);
    Ok(())
}
