//! Failed change attempts leave an audit entry, so "see audit log" points at one.

use core::net::SocketAddr;

use kcc_app::audit::read_entries;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};

use super::support::{Env, TestResult, router};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_refused_change_is_audited_as_failed_with_its_kind() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_parse_matching("ip host", 1))
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    let run = env.kcc(&["--yes", "dns", "static-host", "nas.lab.test", "192.0.2.40"])?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    let entries = read_entries(&env.state_dir())?;
    let failed = entries
        .iter()
        .find(|entry| entry.action == "cli.change")
        .ok_or_else(|| format!("no failed change entry: {entries:?}"))?;
    assert_eq!(failed.outcome, "failed");
    assert_eq!(failed.router.as_deref(), Some("lab-1"));
    assert_eq!(
        failed
            .params_redacted
            .get("error")
            .and_then(|kind| kind.as_str()),
        Some("router"),
        "{failed:?}"
    );
    handle.shutdown().await?;
    Ok(())
}
