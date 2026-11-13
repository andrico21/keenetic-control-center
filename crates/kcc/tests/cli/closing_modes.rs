//! Each closing step sends the router command of the target's recovery mode.

use kcc_testkit::FaultInjection;

use super::{
    closing::{run_id, target},
    support::TestResult,
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
