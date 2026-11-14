//! The router log.
//!
//! The latest lines with a filter, the live stream that opens with the current lines and
//! is capped per session, and the download as a text file.

use core::{str, time::Duration};

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use tokio::time::{Instant, timeout_at};

use crate::support::{
    outcome::TestResult,
    page::{header_text, text},
    web::Fixture,
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/logs";

/// The stream under test.
const STREAM: &str = "/ui/sse/r/home/system/logs";

#[tokio::test]
async fn the_log_shows_its_lines_with_a_filter() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get(PAGE, &viewer).await?).await?;
    for shown in [
        "<li class=\"log-lines__line\">router log text</li>",
        "sse-connect=\"/ui/sse/r/home/system/logs\"",
        "href=\"/ui/r/home/system/logs/download\"",
    ] {
        assert!(page.contains(shown), "missing {shown}");
    }
    let filtered = text(fixture.get(&format!("{PAGE}?q=kernel"), &viewer).await?).await?;
    assert!(
        !filtered.contains("router log text"),
        "the filter hides the line"
    );
    assert!(
        filtered.contains("sse-connect=\"/ui/sse/r/home/system/logs?q=kernel\""),
        "the stream filters too"
    );
    Ok(())
}

#[tokio::test]
async fn the_live_stream_opens_with_the_current_lines_and_is_capped() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let response = fixture.get(STREAM, &viewer).await?;
    assert_eq!(response.status(), StatusCode::OK, "stream");
    assert_eq!(
        header_text(&response, "content-type").as_deref(),
        Some("text/event-stream"),
        "server-sent events"
    );
    let mut body = response.into_body().into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("deadline")?;
    let mut received = String::new();
    while !received.contains("</ol>") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    assert!(received.starts_with("event: tail"), "{received}");
    assert!(received.contains("router log text"), "{received}");
    let mut open = Vec::new();
    for _ in 0_u8..3 {
        open.push(fixture.get(STREAM, &viewer).await?);
    }
    let refused = fixture.get(STREAM, &viewer).await?;
    assert_eq!(
        refused.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "four streams per session"
    );
    drop((body, open));
    Ok(())
}

#[tokio::test]
async fn the_log_downloads_as_a_text_file() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let response = fixture.get(&format!("{PAGE}/download"), &viewer).await?;
    assert_eq!(response.status(), StatusCode::OK, "download");
    assert_eq!(
        header_text(&response, "content-disposition").as_deref(),
        Some("attachment; filename=\"home-log.txt\""),
        "a file"
    );
    assert_eq!(text(response).await?, "router log text\n", "the lines");
    assert!(fixture.audited("web.log_download", "success")?, "audited");
    Ok(())
}
