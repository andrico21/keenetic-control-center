//! A change the router applied while another process holds the audit append lock is
//! reported as applied, with its entry pending, never as a failure.

use std::thread;

use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::{Value, json};

use super::support::{Env, TestResult, router};

/// `kcc <output> --router <router> --yes rci post ip host`.
fn post_host<'arg>(output: &'arg [&'arg str], router: &'arg str) -> Vec<&'arg str> {
    let mut args = output.to_vec();
    args.extend_from_slice(&[
        "--router",
        router,
        "--yes",
        "rci",
        "post",
        "ip",
        "host",
        "--data",
        r#"{"domain":"cli.example","address":"192.0.2.12"}"#,
    ]);
    args
}

/// The ordinary write exits 0 with the note and `audit_pending`.
///
/// Each run waits its bounded time for the receipt; the JSON and human runs go to two
/// routers at once, so that neither waits for the other's lease.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_write_under_a_held_lock_exits_zero_with_its_entry_pending() -> TestResult {
    let (json_address, json_router) = FakeRouter::spawn().await?;
    let (human_address, human_router) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&format!(
        "{}{}",
        router("lab-1", json_address, &password),
        router("lab-2", human_address, &password)
    ))?;
    let lock = StateStore::open(&env.state_dir())?.try_lock(AUDIT_FILE_NAME)?;

    let (json_joined, human_outcome) = thread::scope(|scope| {
        let json_run = scope.spawn(|| {
            env.kcc(&post_host(&["--json"], "lab-1"))
                .map_err(|error| error.to_string())
        });
        let human_run = env.kcc(&post_host(&[], "lab-2"));
        (json_run.join(), human_run)
    });

    drop(lock);
    let json_run = json_joined.map_err(|_panic| "the JSON run panicked")??;
    let human_run = human_outcome?;
    assert_eq!(json_run.code, 0_i32, "{json_run:?}");
    let document: Value = serde_json::from_str(&json_run.stdout)?;
    assert_eq!(
        document.pointer("/items/0/ok"),
        Some(&json!(true)),
        "the router applied it: {document}"
    );
    assert_eq!(document.get("unsaved"), Some(&json!(true)), "{document}");
    assert_eq!(
        document.get("audit_pending"),
        Some(&json!(true)),
        "{document}"
    );
    assert_eq!(human_run.code, 0_i32, "{human_run:?}");
    assert!(
        human_run
            .stderr
            .contains(&tr(Locale::En, keys::AUDIT_ENTRY_PENDING, None)),
        "{human_run:?}"
    );
    let verified = env.kcc(&["audit", "verify"])?;
    assert_eq!(verified.code, 0_i32, "the chain verifies: {verified:?}");
    json_router.shutdown().await?;
    human_router.shutdown().await?;
    Ok(())
}
