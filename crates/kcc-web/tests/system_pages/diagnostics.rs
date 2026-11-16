//! Diagnostics.
//!
//! A ping started as a job streams its replies from the fake router as server-sent events
//! until it ends, Stop ends the router process with `DELETE`, and a bad host is refused
//! before anything is sent.

use core::{str, time::Duration};

use axum::{
    Error as BodyError,
    body::{Body, Bytes},
    http::StatusCode,
};
use futures_util::{StreamExt as _, stream::BoxStream};
use kcc_i18n::keys;
use tokio::time::{Instant, timeout_at};

use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
    web::{Browser, Fixture},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/diagnostics";

/// Starts a ping as `browser` and returns the job's stream and Stop endpoints.
async fn ping(fixture: &Fixture, browser: &Browser) -> TestResult<(String, Option<String>)> {
    let fields = [("tool", "ping"), ("host", "192.0.2.1"), ("count", "3")];
    let panel = text(fixture.post(PAGE, browser, &form(&fields)).await?).await?;
    let attribute = |name: &str| {
        panel
            .split_once(&format!("{name}=\""))
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(value, _)| value.to_owned())
    };
    let stream = attribute("sse-connect").ok_or("no job stream")?;
    let stop = attribute("hx-post").filter(|href| href.ends_with("/cancel"));
    Ok((stream, stop))
}

/// The data of a response body.
type Chunks = BoxStream<'static, Result<Bytes, BodyError>>;

/// Reads `body` until the stream says `done`.
async fn until_done(mut body: Chunks) -> TestResult<String> {
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
    Ok(received)
}

/// The data stream of a response body.
fn events(body: Body) -> Chunks {
    body.into_data_stream().boxed()
}

#[tokio::test(start_paused = true)]
async fn a_ping_streams_its_replies_until_it_ends() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get(PAGE, &viewer).await?).await?;
    assert!(
        page.contains("hx-post=\"/ui/r/home/system/diagnostics\""),
        "a read: every role may run it"
    );
    let (stream, stop) = ping(&fixture, &viewer).await?;
    assert!(
        stream.starts_with("/ui/sse/r/home/system/jobs/job-"),
        "{stream}"
    );
    assert!(stop.is_some(), "Stop");
    let response = fixture.get(&stream, &viewer).await?;
    assert_eq!(response.status(), StatusCode::OK, "stream");
    let received = until_done(events(response.into_body())).await?;
    let lines = received.matches("event: line").count();
    assert!(lines >= 3, "three replies: {received}");
    assert!(received.matches("event: ").count() >= 3, "events");
    assert!(
        received.contains(&en(keys::WEB_EXPLORER_JOB_COMPLETED)),
        "completed: {received}"
    );
    assert!(received.contains("Reply in 1 ms"), "localized: {received}");
    assert!(
        fixture.audited("web.diagnostics_ping", "started")?,
        "audited"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stop_ends_the_router_process_with_delete() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let (stream, stop) = ping(&fixture, &operator).await?;
    let listening = fixture.get(&stream, &operator).await?;
    let stopped = text(fixture.post(&stop.ok_or("no Stop")?, &operator, "").await?).await?;
    assert!(
        stopped.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "stopped: {stopped}"
    );
    let ending = until_done(events(listening.into_body())).await?;
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
    assert!(
        fixture.audited("web.diagnostics_cancel", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_bad_host_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let refused = fixture
        .post(
            PAGE,
            &operator,
            &form(&[("tool", "ping"), ("host", "bad host")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_DIAG_HOST_ERROR)),
        "the rule"
    );
    assert!(
        fixture
            .handle()
            .request_log()
            .iter()
            .all(|record| !record.path().starts_with("/rci/tools/")),
        "no diagnostic started"
    );
    assert!(
        fixture.audited("web.diagnostics_ping", "validation_failed")?,
        "audited"
    );
    Ok(())
}

/// `path` with its job id replaced by one no job has.
fn unknown_job(path: &str) -> TestResult<String> {
    let (before, after) = path.split_once("/jobs/").ok_or("no job id")?;
    let rest = after.split_once('/').map_or("", |(_, tail)| tail);
    let id = format!("job-{}", "0".repeat(32));
    Ok(if rest.is_empty() {
        format!("{before}/jobs/{id}")
    } else {
        format!("{before}/jobs/{id}/{rest}")
    })
}

/// W4-02: only the user who started a diagnostic, or a user who manages users, follows
/// or stops it.
///
/// To another reader of the router its stream and Stop answer exactly like a job that
/// does not exist, and nothing reaches the router; the owner and an administrator may
/// follow it, and each may stop it.
#[tokio::test(start_paused = true)]
async fn only_the_owner_or_an_admin_follows_or_stops_a_diagnostic() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let operator = fixture.login("operator").await?;
    let admin = fixture.login("admin").await?;
    let (stream, offered) = ping(&fixture, &viewer).await?;
    let stop = offered.ok_or("no Stop")?;
    let other_stream = fixture.get(&stream, &operator).await?.status();
    let absent_stream = fixture
        .get(&unknown_job(&stream)?, &operator)
        .await?
        .status();
    let other_stop = fixture.post(&stop, &operator, "").await?.status();
    let absent_stop = fixture
        .post(&unknown_job(&stop)?, &operator, "")
        .await?
        .status();
    assert_eq!(
        (other_stream, other_stop),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
        "another user's job"
    );
    assert_eq!(
        (other_stream, other_stop),
        (absent_stream, absent_stop),
        "answers like a missing job"
    );
    let deletes = || {
        fixture
            .handle()
            .request_log()
            .iter()
            .filter(|record| record.method().as_str() == "DELETE")
            .count()
    };
    assert_eq!(deletes(), 0, "a refused Stop reaches no router");
    let watched = fixture.get(&stream, &admin).await?;
    assert_eq!(watched.status(), StatusCode::OK, "an administrator follows");
    drop(watched);
    let listening = fixture.get(&stream, &viewer).await?;
    assert_eq!(listening.status(), StatusCode::OK, "the owner follows");
    let by_owner = text(fixture.post(&stop, &viewer, "").await?).await?;
    assert!(
        by_owner.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "the owner stops: {by_owner}"
    );
    drop(until_done(events(listening.into_body())).await?);
    let (_, second) = ping(&fixture, &viewer).await?;
    let by_admin = text(fixture.post(&second.ok_or("no Stop")?, &admin, "").await?).await?;
    assert!(
        by_admin.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "an administrator stops: {by_admin}"
    );
    Ok(())
}
