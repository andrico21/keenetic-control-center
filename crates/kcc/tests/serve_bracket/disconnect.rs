//! An MCP management change keeps its bracket when its HTTP reply goes away: the client
//! disconnects and cancels the call, or the call outlasts `[server] request_timeout`.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{sync::Mutex, time::Instant};

use kcc_app::audit::verify_chain;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpStream,
    sync::Notify,
    task::block_in_place,
    time::{sleep, timeout},
};

use super::{ARM, DISARM, disarmed};
use crate::{
    mcp,
    process::{PROCESS_TIMEOUT, Served},
    proxy::Action,
    support::TestResult,
};

/// The management line every call sends.
const LINE: &str = "no interface Bridge0";

/// Upper bound for the disarm to reach the router once the arm is released.
const DISARM_WAIT: Duration = Duration::from_secs(20);

/// What happened, in order.
type Events = Arc<Mutex<Vec<&'static str>>>;

/// Appends `event` to `events`; a poisoned lock loses it, which the order check reports.
fn note(events: &Events, event: &'static str) {
    if let Ok(mut seen) = events.lock() {
        seen.push(event);
    }
}

/// Sends the `kcc_cli_parse` call for `LINE` on `session` over a raw connection that
/// nothing reads.
async fn unread_call(base: &str, key: &str, session: &str) -> TestResult<TcpStream> {
    let host = base.strip_prefix("http://").ok_or("base URL")?;
    let body = serde_json::to_vec(&mcp::cli_call(LINE))?;
    let head = format!(
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {key}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMcp-Session-Id: {session}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(host).await?;
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(stream)
}

/// Stops `served` and returns the audit entries for the router's recovery timer and for
/// the change.
fn audited(served: &mut Served) -> TestResult<(usize, usize)> {
    served.terminate()?;
    let _exited =
        block_in_place(|| served.exit_within(PROCESS_TIMEOUT))?.ok_or("kcc serve did not exit")?;
    let entries = verify_chain(&served.state_dir())?;
    let count = |target: &str| {
        entries
            .iter()
            .filter(|entry| {
                entry.action == "router.change_cli" && entry.target.as_deref() == Some(target)
            })
            .count()
    };
    Ok((
        count("system configuration fail-safe timer"),
        count("interface"),
    ))
}

/// A client that drops the connection of its management call once the router has seen
/// the arm, and cancels the call, gets no reply; the bracket still disarms, audits, and
/// the server keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_mcp_bracket_outlives_a_disconnected_client() -> TestResult {
    let events: Events = Arc::default();
    let (armed, closed, reached) = (
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    );
    let (at_arm, gate, arm_log) = (Arc::clone(&armed), Arc::clone(&closed), Arc::clone(&events));
    let hold: Action = Box::new(move || {
        Box::pin(async move {
            note(&arm_log, "arm-seen");
            at_arm.notify_one();
            gate.notified().await;
            note(&arm_log, "arm-forwarded");
        })
    });
    let (at_disarm, disarm_log) = (Arc::clone(&reached), Arc::clone(&events));
    let seen: Action = Box::new(move || {
        Box::pin(async move {
            note(&disarm_log, "disarm");
            at_disarm.notify_one();
        })
    });
    let (mut served, _lines) = Served::start(("", true), |_audit| {
        vec![(ARM, hold), (DISARM.as_bytes(), seen)]
    })
    .await?;
    let (client, base, key) = served.mcp();
    let session = mcp::open(&client, (&base, &key)).await?;

    let connection = unread_call(&base, &key, &session).await?;
    timeout(PROCESS_TIMEOUT, armed.notified())
        .await
        .map_err(|_elapsed| "the arm never reached the router")?;
    drop(connection);
    note(&events, "client-closed");
    mcp::cancel(&client, (&base, &key, &session)).await?;
    note(&events, "cancel-accepted");
    closed.notify_one();
    timeout(DISARM_WAIT, reached.notified())
        .await
        .map_err(|_elapsed| "the disarm never reached the router")?;

    assert_eq!(
        served.exit_within(Duration::ZERO)?,
        None,
        "kcc serve still runs"
    );
    let fresh = mcp::open(&client, (&base, &key)).await?;
    assert!(!fresh.is_empty(), "a new MCP session opens");
    assert!(disarmed(&served), "the disarm reached the router");
    assert!(
        !served.router().recovery_armed(),
        "the router's timer is off"
    );
    assert_eq!(
        events.lock().map_err(|_poison| "events lock")?.as_slice(),
        [
            "arm-seen",
            "client-closed",
            "cancel-accepted",
            "arm-forwarded",
            "disarm"
        ],
        "the client was gone before the arm was answered"
    );
    assert_eq!(
        audited(&mut served)?,
        (2, 1),
        "arm, disarm and the change audited"
    );
    Ok(())
}

/// A management call that outlasts `request_timeout = "1s"` still gets its reply: the
/// kit's request timeout ends when the SSE response starts, not when the call ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_mcp_bracket_outlasting_the_request_timeout_answers() -> TestResult {
    let started = Arc::new(Notify::new());
    let gate = Arc::clone(&started);
    let hold: Action = Box::new(move || {
        Box::pin(async move {
            gate.notified().await;
            // Time is the behavior under test: the call must outlast the 1 s timeout.
            sleep(Duration::from_secs(2)).await;
        })
    });
    let (mut served, _lines) = Served::start(("request_timeout = \"1s\"\n", true), |_audit| {
        vec![(ARM, hold)]
    })
    .await?;
    let (client, base, key) = served.mcp();
    let begun = Instant::now();

    let response = mcp::cli_parse(&client, (&base, &key), LINE).await?;
    started.notify_one();
    assert_eq!(response.status(), StatusCode::OK, "the SSE reply started");
    let body = response.text().await?;
    let elapsed = begun.elapsed();

    let reply = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|message| message.get("id") == Some(&Value::from(2_u32)))
        .ok_or("no reply to the call")?;
    assert!(
        elapsed > Duration::from_secs(1),
        "the call outlasted the timeout"
    );
    assert!(reply.get("result").is_some(), "a tool result: {reply}");
    assert_ne!(
        reply.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "the call succeeded: {reply}"
    );
    assert!(disarmed(&served), "the disarm reached the router");
    assert_eq!(
        audited(&mut served)?,
        (2, 1),
        "arm, disarm and the change audited"
    );
    Ok(())
}
