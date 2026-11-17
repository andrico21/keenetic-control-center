//! The log page and its live stream follow the router's log collector.
//!
//! With the collector running, five concurrent viewers add no `show log` request at the
//! router: the collector's one stream start stays the only one. Without it, the viewers
//! share one poller that reads the router once.

use core::{iter, str, time::Duration};

use futures_util::{StreamExt as _, future::try_join_all};
use serde_json::json;
use tokio::time::{Instant, timeout, timeout_at};

use crate::{
    support::{Fixture, ROUTER, TestResult},
    wiring::{Options, text},
};

/// The log page.
const PAGE: &str = "/ui/r/home/system/logs";

/// The live log stream.
const STREAM: &str = "/ui/sse/r/home/system/logs";

/// Viewers opened at once.
const VIEWERS: usize = 5;

/// The router's one log line.
const LINE: &str = "collected line";

/// One viewer: signs in, loads the page, and reads the stream's opening lines.
async fn view(fixture: &Fixture) -> TestResult<(String, String)> {
    let browser = fixture.login().await?;
    let page = text(fixture.get(PAGE, &browser).await?).await?;
    let mut body = fixture
        .get(STREAM, &browser)
        .await?
        .into_body()
        .into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("deadline")?;
    let mut opening = String::new();
    while !opening.contains("</ol>") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        opening.push_str(str::from_utf8(&chunk)?);
    }
    Ok((page, opening))
}

/// Puts the router's one log record in place.
fn log_line(fixture: &Fixture) {
    fixture.handle().insert_log(
        7,
        json!({"message":{"label":"I","message":format!("[Jan 01 00:00:00] {LINE}")}}),
    );
}

#[tokio::test]
async fn concurrent_viewers_add_no_router_log_request() -> TestResult {
    let fixture = Fixture::new(Options::collector()).await?;
    let mut collected = fixture
        .logs()
        .and_then(|logs| logs.subscribe(ROUTER))
        .ok_or("the collector follows the router")?;
    log_line(&fixture);
    let record = timeout(Duration::from_secs(30), collected.recv()).await??;
    assert!(record.message.contains(LINE), "collected");
    let reads = fixture.log_reads();
    assert_eq!(reads, 1, "the collector's stream start");

    let views = try_join_all(iter::repeat_with(|| view(&fixture)).take(VIEWERS)).await?;
    for (page, opening) in &views {
        assert!(page.contains(LINE), "the page shows the collected line");
        assert!(opening.contains(LINE), "the stream opens with it");
    }
    assert_eq!(fixture.log_reads(), reads, "zero extra show log requests");
    assert_eq!(fixture.handle().log_streams(), 1, "one router log stream");
    Ok(())
}

/// W4-13: without a collector, concurrent viewers of one router's log share one poller:
/// opening five live streams costs the router one `show log` read, not five.
#[tokio::test]
async fn without_the_collector_viewers_share_one_router_read() -> TestResult {
    let fixture = Fixture::new(Options::default()).await?;
    log_line(&fixture);
    let mut bodies = Vec::new();
    for _ in 0..VIEWERS {
        let browser = fixture.login().await?;
        bodies.push(
            fixture
                .get(STREAM, &browser)
                .await?
                .into_body()
                .into_data_stream(),
        );
    }
    for body in &mut bodies {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or("deadline")?;
        let mut opening = String::new();
        while !opening.contains("</ol>") {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended")??;
            opening.push_str(str::from_utf8(&chunk)?);
        }
        assert!(opening.contains(LINE), "the stream opens with the line");
    }
    assert_eq!(fixture.log_reads(), 1, "one shared read for every viewer");
    assert_eq!(
        fixture.handle().log_streams(),
        0,
        "no stream without a collector"
    );
    drop(bodies);
    Ok(())
}
