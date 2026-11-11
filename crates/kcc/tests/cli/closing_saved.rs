//! Saved-configuration receipts for resumed finishes.

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;
use serde_json::json;

use super::{
    closing::{run_id, target},
    support::TestResult,
};

/// A saved migration or preset names persistence when disarm is refused or lost.
// NOT cancel-safe: saves the fixture configuration before requesting disarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_saved_disarm_failure_reports_persistence() -> TestResult {
    let mut failures = Vec::new();
    for path in ["preset", "migrate"] {
        for lost in [false, true] {
            let faults = if lost {
                FaultInjection::default().disconnect_before_parse("no system reboot".to_owned())
            } else {
                FaultInjection::default().fail_parse_matching("no system reboot", 1)
            };
            let (env, handle) = target("extender", faults).await?;
            let arm = env.kcc(&[
                "--confirm-destructive",
                "target",
                "config",
                "failsafe",
                "arm",
            ])?;
            assert_eq!(arm.code, 0_i32, "{arm:?}");
            let changed = env.kcc(&["system", "set-description", "saved-finish"])?;
            assert_eq!(changed.code, 0_i32, "{changed:?}");
            let job = run_id(&env).await?;

            let run = if path == "preset" {
                env.kcc(&["--yes", "preset", "finish", &job, "save"])?
            } else {
                env.kcc(&["migrate", "finish", "commit"])?
            };

            let entries = read_entries(&env.state_dir())?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "cli.change" && entry.outcome == "failed")
                .ok_or("missing failed finish audit")?;
            if run.code != 6_i32
                || !run
                    .stderr
                    .contains(&tr(Locale::En, keys::FINISH_SAVED_ARMED, None))
                || run
                    .stderr
                    .contains(&tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None))
                || failed.params_redacted.get("fail_safe_armed") != Some(&json!(true))
                || !handle.recovery_armed()
                || !handle.startup_config_text().contains("saved-finish")
            {
                failures.push(format!("{path} lost={lost}: {run:?}; audit={failed:?}"));
            }
            handle.shutdown().await?;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
