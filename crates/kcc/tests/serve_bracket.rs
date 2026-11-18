//! `kcc serve` finishes every open management bracket before it exits.
//!
//! A Web bracket whose arm receipt kills the audit writer still sends the disarm and the
//! browser still gets the outcome before the server exits non-zero; a bracket that
//! outlives the listener's drain, on the Web or over MCP, keeps the process alive until
//! it has disarmed. An MCP bracket also outlives the loss of its HTTP reply.
#![cfg(unix)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_bracket/disconnect.rs"]
mod disconnect;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_bracket/mcp.rs"]
mod mcp;
#[path = "serve_bracket/process.rs"]
mod process;
#[path = "serve_bracket/proxy.rs"]
mod proxy;
#[path = "support/serve_port.rs"]
mod serve_port;
#[expect(
    dead_code,
    reason = "the server suites stop the process with SIGTERM only"
)]
#[path = "support/signal.rs"]
mod signal;
#[path = "support/spawning.rs"]
mod spawning;
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
use core::error::Error;
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use kcc_app::audit::verify_chain;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use reqwest::StatusCode;
use tokio::{
    sync::Notify,
    task::{block_in_place, spawn_blocking},
    time::timeout,
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

/// The log line of a listener drain that ran out of `shutdown_timeout`.
const DRAIN_ENDED: &str = "shutdown timeout exceeded";

/// The log line `kcc serve` writes after its open brackets closed, on its way to exit.
const JOBS_DRAINED: &str = "jobs drained";

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
    let (mut served, _lines) =
        Served::start(("", false), |audit| vec![(ARM, freeze(audit))]).await?;

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
        body.contains(&html(&tr(Locale::En, keys::WEB_EXPLORER_FAILED, None))),
        "the dead writer is the change's failure: {body}"
    );
    assert!(
        !body.contains(&html(&tr(
            Locale::En,
            keys::MANAGEMENT_NOT_SENT_ARMED,
            None
        ))),
        "the disarm was accepted, so the timer is not reported armed: {body}"
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
    let (mut served, lines) = Served::start(("shutdown_timeout = \"1s\"\n", false), |audit| {
        vec![(ARM, freeze(audit)), (DISARM.as_bytes(), hold)]
    })
    .await?;

    let forced = spawn_blocking(move || {
        wait_line(&lines, DRAIN_ENDED)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(lines)
    });
    let after_drain = {
        let request = served.management_change();
        tokio::pin!(request);
        tokio::select! {
            answered = &mut request => {
                return Err(format!("answered before the drain ended: {answered:?}").into());
            }
            waited = forced => waited??,
        }
    };
    assert!(!disarmed(&served), "the relay holds the disarm");
    released.notify_one();
    spawn_blocking(move || wait_line(&after_drain, JOBS_DRAINED)).await??;

    assert!(
        disarmed(&served),
        "the router had the disarm before the process went on to exit"
    );
    let status =
        block_in_place(|| served.exit_within(PROCESS_TIMEOUT))?.ok_or("kcc serve did not exit")?;
    assert!(
        !served.router().recovery_armed(),
        "the router's timer is off"
    );
    assert_eq!(status.code(), Some(1_i32));
    Ok(())
}

/// An MCP management change whose disarm the relay holds back keeps a SIGTERM'd server,
/// past its listener's drain (`shutdown_timeout = "1s"`), alive until the router has the
/// disarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_mcp_bracket_disarms_before_a_terminated_server_exits() -> TestResult {
    let (reached, released) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let (at_disarm, gate) = (Arc::clone(&reached), Arc::clone(&released));
    let hold: Action = Box::new(move || {
        Box::pin(async move {
            at_disarm.notify_one();
            gate.notified().await;
        })
    });
    let (mut served, lines) = Served::start(("shutdown_timeout = \"1s\"\n", true), |_audit| {
        vec![(DISARM.as_bytes(), hold)]
    })
    .await?;
    let (client, base, key) = served.mcp();
    let mut call = tokio::spawn(async move {
        let response = mcp::cli_parse(&client, (&base, &key), "no interface Bridge0").await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(response.text().await?)
    });
    timeout(PROCESS_TIMEOUT, async {
        tokio::select! {
            () = reached.notified() => Ok(()),
            answered = &mut call => Err(format!("answered before the disarm: {answered:?}")),
        }
    })
    .await??;

    served.terminate()?;
    let after_drain = spawn_blocking(move || {
        wait_line(&lines, DRAIN_ENDED)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(lines)
    })
    .await??;
    assert!(!disarmed(&served), "the relay holds the disarm");
    released.notify_one();
    spawn_blocking(move || wait_line(&after_drain, JOBS_DRAINED)).await??;
    let exited = block_in_place(|| served.exit_within(PROCESS_TIMEOUT))?;
    call.abort();

    assert!(
        disarmed(&served),
        "the router had the disarm before the process went on to exit"
    );
    assert!(exited.is_some(), "kcc serve exited");
    assert!(
        !served.router().recovery_armed(),
        "the router's timer is off"
    );
    Ok(())
}
