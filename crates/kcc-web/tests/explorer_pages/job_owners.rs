//! Who may follow or stop an explorer job.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
    web::{Browser, Fixture},
};

/// Starts a background ping as `browser` and returns its stream and Stop endpoints.
async fn ping(fixture: &Fixture, browser: &Browser) -> TestResult<(String, String)> {
    let fields = form(&[
        ("path", "tools ping"),
        ("a.host", "192.0.2.1"),
        ("a.count", "3"),
        ("confirm", "yes"),
    ]);
    let panel = text(
        fixture
            .post("/ui/r/home/explorer/execute", browser, &fields)
            .await?,
    )
    .await?;
    let attribute = |name: &str| {
        panel
            .split_once(&format!("{name}=\""))
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(value, _)| value.to_owned())
    };
    let stream = attribute("sse-connect").ok_or("no job stream")?;
    let stop = attribute("hx-post")
        .filter(|href| href.ends_with("/cancel"))
        .ok_or("no Stop")?;
    Ok((stream, stop))
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

/// W4-02: only the user who started an explorer job, or a user who manages users,
/// follows or stops it.
///
/// To another reader of the router its stream and Stop answer exactly like a job that
/// does not exist, and nothing reaches the router; the owner and an administrator may
/// follow it, and each may stop it.
#[tokio::test(start_paused = true)]
async fn only_the_owner_or_an_admin_follows_or_stops_an_explorer_job() -> TestResult {
    let fixture = Fixture::new().await?;
    let owner = fixture.login("raw-writer").await?;
    let viewer = fixture.login("viewer").await?;
    let admin = fixture.login("admin").await?;
    let (stream, stop) = ping(&fixture, &owner).await?;
    let other_stream = fixture.get(&stream, &viewer).await?.status();
    let absent_stream = fixture.get(&unknown_job(&stream)?, &viewer).await?.status();
    let other_stop = fixture.post(&stop, &viewer, "").await?.status();
    let absent_stop = fixture
        .post(&unknown_job(&stop)?, &viewer, "")
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
    assert!(
        fixture
            .handle()
            .request_log()
            .iter()
            .all(|record| record.method().as_str() != "DELETE"),
        "a refused Stop reaches no router"
    );
    let watched = fixture.get(&stream, &admin).await?;
    assert_eq!(watched.status(), StatusCode::OK, "an administrator follows");
    drop(watched);
    let listening = fixture.get(&stream, &owner).await?;
    assert_eq!(listening.status(), StatusCode::OK, "the owner follows");
    drop(listening);
    let by_owner = text(fixture.post(&stop, &owner, "").await?).await?;
    assert!(
        by_owner.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "the owner stops: {by_owner}"
    );
    let (_, second) = ping(&fixture, &owner).await?;
    let by_admin = text(fixture.post(&second, &admin, "").await?).await?;
    assert!(
        by_admin.contains(&en(keys::WEB_EXPLORER_JOB_STOPPED)),
        "an administrator stops: {by_admin}"
    );
    Ok(())
}
