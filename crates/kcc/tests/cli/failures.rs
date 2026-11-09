//! Failed change attempts leave an audit entry, so "see audit log" points at one.

use core::net::SocketAddr;

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};

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

/// A change the router accepts but does not apply exits 6 under its own headline, not
/// the unreachable-router one, and names the field that read back unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_that_reads_back_unchanged_says_the_router_did_not_apply_it() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().silent_noop_path("parse"))
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    let run = env.kcc(&["--json", "--yes", "services", "set", "telnet", "on"])?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    let last = run.stderr.lines().last().ok_or("no error line")?;
    let document: Value = serde_json::from_str(last)?;
    let error = document.get("error").ok_or("no error object")?;
    assert_eq!(error.get("kind"), Some(&json!("router")), "{document}");
    assert_eq!(
        error.get("message"),
        Some(&json!(tr(Locale::En, keys::CLI_ERROR_NOT_APPLIED, None))),
        "{document}"
    );
    assert!(
        error
            .get("details")
            .is_some_and(|details| details.to_string().contains("/service")),
        "{document}"
    );
    handle.shutdown().await?;
    Ok(())
}
