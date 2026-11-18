//! Firewall binding process-level behavior.

use core::net::SocketAddr;

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};

use super::support::{Env, TestResult, router};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applied_firewall_binding_exits_zero_and_is_audited() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .reached_directly()
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    let run = env.kcc(&["firewall", "bind", "WebAcl", "--interface", "ISP"])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        !run.stderr
            .contains(&tr(Locale::En, keys::CLI_ERROR_FIREWALL_VERIFICATION, None)),
        "no failed read-back is reported: {run:?}"
    );
    assert!(
        read_entries(&env.state_dir())?
            .iter()
            .any(|entry| entry.outcome == "applied_unsaved")
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignored_firewall_binding_reports_failed_read_back() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().silent_noop_path("parse"))
        .reached_directly()
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    let run = env.kcc(&["firewall", "bind", "WebAcl", "--interface", "ISP"])?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::CLI_ERROR_FIREWALL_VERIFICATION, None)),
        "{run:?}"
    );
    assert!(
        !read_entries(&env.state_dir())?
            .iter()
            .any(|entry| entry.outcome == "applied_unsaved")
    );
    handle.shutdown().await?;
    Ok(())
}
