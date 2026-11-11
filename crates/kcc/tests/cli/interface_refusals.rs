//! Interface guard refusals distinguish unknown work from an unarmed bracket.

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
use serde_json::json;

use super::support::{Env, TestResult, router};

/// Work refusal retains recovery; arm refusal never claims work was applied or armed.
// NOT cancel-safe: the fixture may arm recovery before rejecting the interface change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interface_refusals_preserve_armed_outcome() -> TestResult {
    for (prefix, armed) in [
        ("interface Bridge0 security-level", true),
        ("system configuration fail-safe timer", false),
    ] {
        let (address, handle) = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching(prefix, 1))
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;

        let run = env.kcc(&[
            "--yes",
            "interfaces",
            "security-level",
            "Bridge0",
            "private",
        ])?;

        assert_eq!(run.code, 6_i32, "{run:?}");
        assert_eq!(handle.recovery_armed(), armed);
        let key = if armed {
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
        } else {
            keys::CLI_ERROR_ROUTER
        };
        assert!(run.stderr.contains(&tr(Locale::En, key, None)), "{run:?}");
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::MANAGEMENT_DISARM_FAILED, None)),
            "{run:?}"
        );
        let entries = read_entries(&env.state_dir())?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "cli.change")
            .ok_or("missing interface refusal audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            armed.then_some(&json!(true))
        );
        assert!(
            !handle
                .request_log()
                .iter()
                .any(|record| record.command() == Some("no system configuration fail-safe timer")),
            "refusal does not disarm"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
