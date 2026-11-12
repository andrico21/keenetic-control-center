//! `kcc serve` finishes a Web management bracket when the audit writer dies inside it.
//!
//! The arm reaches the router, then the audit log turns read-only, so the arm receipt is
//! a fatal writer failure and the server must exit non-zero. It must not exit first: the
//! request still sends the disarm and the browser still gets the outcome (F3 round 17
//! N73, F4 N75).
#![cfg(unix)]
#![expect(
    clippy::integer_division_remainder_used,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process; tokio::select expands to `%`"
)]

#[path = "serve_bracket/process.rs"]
mod process;
#[path = "serve_bracket/proxy.rs"]
mod proxy;
#[path = "serve_bracket/support.rs"]
mod support;
#[expect(
    dead_code,
    reason = "the shared browser; this suite needs only sign-in and posts"
)]
#[path = "serve_refresh/web.rs"]
mod web;

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use kcc_app::audit::verify_chain;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use reqwest::StatusCode;
use tokio::{
    sync::Notify,
    task::{block_in_place, spawn_blocking},
};

use crate::{
    process::{PROCESS_TIMEOUT, Served, wait_line},
    proxy::Action,
    support::TestResult,
};

/// The router-mode arm line, as the relay sees it.
const ARM: &[u8] = b"fail-safe timer reboot";

/// The router-mode disarm line.
const DISARM: &str = "no system configuration fail-safe timer";

/// `text` as askama escapes it.
fn html(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Makes the audit log read-only once the arm passes, so the arm receipt kills the writer.
fn freeze(audit: PathBuf) -> Action {
    Box::new(move || {
        Box::pin(async move {
            drop(fs::set_permissions(
                &audit,
                fs::Permissions::from_mode(0o444),
            ));
        })
    })
}

/// Whether the router received the disarm.
fn disarmed(served: &Served) -> bool {
    served
        .router()
        .request_log()
        .iter()
        .any(|record| record.command() == Some(DISARM))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_audit_writer_waits_for_the_web_bracket_to_close() -> TestResult {
    let (mut served, _lines) = Served::start("", |audit| vec![(ARM, freeze(audit))]).await?;

    let answered = served.management_change().await;
    let status =
        block_in_place(|| served.exit_within(PROCESS_TIMEOUT))?.ok_or("kcc serve did not exit")?;

    let response = answered?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an answer, not a closed connection"
    );
    let body = response.text().await?;
    assert!(
        body.contains(&html(&tr(
            Locale::En,
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            None
        ))),
        "{body}"
    );
    assert!(disarmed(&served), "the disarm reached the router");
    assert!(
        !served.router().recovery_armed(),
        "the router's timer is off"
    );
    assert_eq!(
        status.code(),
        Some(1_i32),
        "the dead writer still ends the server"
    );
    assert!(
        !verify_chain(&served.state_dir())?.is_empty(),
        "chain intact"
    );
    Ok(())
}

/// A bracket that outlives the listener's drain (`shutdown_timeout = "1s"`, the disarm
/// held back at the relay) keeps the process alive until it has disarmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bracket_outliving_the_drain_disarms_before_exit() -> TestResult {
    let released = Arc::new(Notify::new());
    let gate = Arc::clone(&released);
    let hold: Action = Box::new(move || Box::pin(async move { gate.notified().await }));
    let (mut served, lines) = Served::start("shutdown_timeout = \"1s\"\n", |audit| {
        vec![(ARM, freeze(audit)), (DISARM.as_bytes(), hold)]
    })
    .await?;

    let forced = spawn_blocking(move || wait_line(&lines, "shutdown timeout exceeded"));
    {
        let request = served.management_change();
        tokio::pin!(request);
        tokio::select! {
            answered = &mut request => {
                return Err(format!("answered before the drain ended: {answered:?}").into());
            }
            waited = forced => waited??,
        }
    }
    let early = block_in_place(|| served.exit_within(Duration::from_secs(3)))?;
    assert_eq!(early, None, "still running while the bracket is open");
    released.notify_one();
    let status =
        block_in_place(|| served.exit_within(PROCESS_TIMEOUT))?.ok_or("kcc serve did not exit")?;

    assert!(disarmed(&served), "the disarm reached the router");
    assert!(
        !served.router().recovery_armed(),
        "the router's timer is off"
    );
    assert_eq!(status.code(), Some(1_i32));
    Ok(())
}
