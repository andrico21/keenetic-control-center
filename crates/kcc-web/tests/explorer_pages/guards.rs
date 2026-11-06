//! Guarded execution: destructive confirmations, the fail-safe timer around management
//! changes, and background commands run as jobs.

use core::{str, time::Duration};

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use futures_util::StreamExt as _;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciBody, RciPath};
use serde_json::Value;
use tokio::time::{Instant, timeout_at};

use crate::{
    en, form, html,
    support::{Fixture, ROUTER, TestResult, text},
};

/// A destructive command needs the exact router name; an operator may not run it.
#[tokio::test]
async fn destructive_commands_need_the_router_name() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(fixture.get("/ui/r/home/explorer", &admin).await?);
    let before = fixture.handle().request_count();
    let path = [
        ("path", "system configuration factory-reset"),
        ("confirm", "yes"),
    ];
    let asked = text(
        fixture
            .post("/ui/r/home/explorer/execute", &admin, &form(&path))
            .await?,
    )
    .await?;
    assert!(
        asked.contains("name=\"confirm_name\""),
        "name field: {asked}"
    );
    let mut wrong = path.to_vec();
    wrong.push(("confirm_name", "Home"));
    let refused = text(
        fixture
            .post("/ui/r/home/explorer/execute", &admin, &form(&wrong))
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    let error = html(&tr(
        Locale::En,
        keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
        Some(&args),
    ));
    assert!(refused.contains(&error), "mismatch: {refused}");
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let operator = fixture.login("operator").await?;
    let denied = fixture
        .post("/ui/r/home/explorer/execute", &operator, &form(&path))
        .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    Ok(())
}

/// A management change runs under the fail-safe timer, which is disarmed afterwards.
#[tokio::test]
async fn management_changes_run_under_the_fail_safe_timer() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let fields = [("path", "ip http port"), ("a.port", "8080")];
    let asked = text(
        fixture
            .post("/ui/r/home/explorer/execute", &browser, &form(&fields))
            .await?,
    )
    .await?;
    assert!(
        asked.contains(&en(keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TITLE)),
        "fail-safe dialog"
    );
    let mut confirmed = fields.to_vec();
    confirmed.push(("confirm", "yes"));
    let body = text(
        fixture
            .post("/ui/r/home/explorer/execute", &browser, &form(&confirmed))
            .await?,
    )
    .await?;
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
        "applied: {body}"
    );
    let cli: Vec<_> = fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.action == "router.change_cli")
        .map(|entry| entry.target.unwrap_or_default())
        .collect();
    assert_eq!(
        cli,
        [
            "system configuration fail-safe timer",
            "system configuration fail-safe timer"
        ],
        "armed, then disarmed"
    );
    let client = fixture.registry().client(ROUTER).await?;
    let state = client
        .show(&RciPath::from_segments(["show", "last-change"])?, &())
        .await?;
    assert!(
        matches!(&state, RciBody::Json(response)
            if response.value.pointer("/fail-safe/active") == Some(&Value::Bool(false))),
        "disarmed: {state:?}"
    );
    Ok(())
}

/// A background command runs as a job: the stream shows its status and final answer,
/// and Stop ends the router process with DELETE.
#[tokio::test(start_paused = true)]
async fn background_commands_run_as_jobs_and_stop() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let ping = form(&[
        ("path", "tools ping"),
        ("a.host", "192.0.2.1"),
        ("a.count", "3"),
        ("confirm", "yes"),
    ]);
    let started = text(
        fixture
            .post("/ui/r/home/explorer/execute", &browser, &ping)
            .await?,
    )
    .await?;
    let stream = started
        .split_once("sse-connect=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(url, _)| url.to_owned())
        .ok_or("no job stream")?;
    assert!(stream.starts_with("/ui/sse/r/home/jobs/job-"), "{stream}");
    let response = fixture.get(&stream, &browser).await?;
    assert_eq!(response.status(), StatusCode::OK, "stream");
    let mut body = response.into_body().into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .ok_or("deadline")?;
    let mut received = String::new();
    while !received.contains("event: done") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    assert!(received.contains("event: output"), "answer: {received}");
    assert!(
        received.contains(&en(keys::WEB_EXPLORER_JOB_COMPLETED)),
        "completed"
    );
    let second = text(
        fixture
            .post("/ui/r/home/explorer/execute", &browser, &ping)
            .await?,
    )
    .await?;
    let second_stream = second
        .split_once("sse-connect=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(url, _)| url.to_owned())
        .ok_or("no second job stream")?;
    let cancel = second
        .split_once("hx-post=\"/ui/r/home/jobs/")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(rest, _)| format!("/ui/r/home/jobs/{rest}"))
        .ok_or("no stop button")?;
    let listening = fixture.get(&second_stream, &browser).await?;
    let mut events = listening.into_body().into_data_stream();
    let stopped = text(fixture.post(&cancel, &browser, "").await?).await?;
    assert!(
        stopped.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "stopped: {stopped}"
    );
    let mut ending = String::new();
    while !ending.contains("event: done") {
        let chunk = timeout_at(deadline, events.next())
            .await?
            .ok_or("stream ended")??;
        ending.push_str(str::from_utf8(&chunk)?);
    }
    assert!(
        ending.contains(&en(keys::WEB_EXPLORER_JOB_CANCELLED_LABEL)),
        "stopped: {ending}"
    );
    assert!(
        fixture.handle().request_log().iter().any(
            |record| record.method().as_str() == "DELETE" && record.path() == "/rci/tools/ping"
        ),
        "the router process was stopped with DELETE"
    );
    Ok(())
}
