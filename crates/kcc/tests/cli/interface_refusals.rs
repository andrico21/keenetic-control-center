//! Interface guard refusals distinguish unknown work from an unarmed bracket.

use kcc_app::audit::read_entries;
use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};

use super::support::{Env, TestResult, router};

/// Work and arm refusals close recovery when disarm remains reachable.
// NOT cancel-safe: the fixture may arm recovery before rejecting the interface change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interface_refusals_preserve_armed_outcome() -> TestResult {
    for prefix in [
        "interface Bridge0 security-level",
        "system configuration fail-safe timer",
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
        assert!(!handle.recovery_armed());
        let entries = read_entries(&env.state_dir())?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "cli.change")
            .ok_or("missing interface refusal audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.params_redacted.get("fail_safe_armed"), None);
        assert!(
            handle
                .request_log()
                .iter()
                .any(|record| record.command() == Some("no system configuration fail-safe timer")),
            "refusal closes recovery"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
