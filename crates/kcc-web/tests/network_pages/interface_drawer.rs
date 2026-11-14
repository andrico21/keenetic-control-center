//! The interface drawer: one interface's settings, counters and controls, and the stream
//! of its traffic.

use core::{str, time::Duration};

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use kcc_i18n::{keys, locale::Locale};
use tokio::time::{Instant, timeout_at};

use crate::{
    interfaces::DISABLE_BRIDGE,
    support::{
        outcome::TestResult,
        page::{header_text, said, text},
        web::Fixture,
    },
};

#[tokio::test]
async fn the_drawer_shows_one_interface_and_its_counters() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let response = fixture
        .get("/ui/r/home/network/detail?name=Bridge0", &viewer)
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "drawer");
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "in the shared dialog"
    );
    let drawer = text(response).await?;
    for shown in [
        "class=\"drawer\"".to_owned(),
        "192.0.2.1/24".to_owned(),
        "02:00:00:00:01:01".to_owned(),
        said(Locale::En, keys::WEB_NETWORK_RECEIVED),
        "sse-connect=\"/ui/sse/r/home/network/traffic?name=Bridge0\"".to_owned(),
        "id=\"traffic-chart\"".to_owned(),
    ] {
        assert!(drawer.contains(&shown), "drawer misses {shown}: {drawer}");
    }
    assert!(!drawer.contains("network/description?"), "viewer: no Edit");
    let admin = fixture.login("admin").await?;
    let editable = text(
        fixture
            .get("/ui/r/home/network/detail?name=Bridge0", &admin)
            .await?,
    )
    .await?;
    for control in [
        "hx-get=\"/ui/r/home/network/description?name=Bridge0\"",
        "hx-get=\"/ui/r/home/network/security-level?name=Bridge0\"",
        DISABLE_BRIDGE,
    ] {
        assert!(editable.contains(control), "admin misses {control}");
    }
    let nested = fixture
        .get(
            "/ui/r/home/network/detail?name=WifiMaster0%2FAccessPoint1",
            &viewer,
        )
        .await?;
    assert_eq!(nested.status(), StatusCode::OK, "a slash name in the query");
    assert!(
        !fixture
            .handle()
            .request_log()
            .iter()
            .any(|record| record.path().contains("AccessPoint")),
        "names never reach a router path"
    );
    let unknown = fixture
        .get("/ui/r/home/network/detail?name=Tunnel9", &viewer)
        .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown interface");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_drawer_stream_sends_rates_from_counter_readings() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let response = fixture
        .get("/ui/sse/r/home/network/traffic?name=Bridge0", &viewer)
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "stream");
    let mut body = response.into_body().into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .ok_or("deadline")?;
    let mut received = String::new();
    while !received.contains("\"rx\":[0]") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    assert!(
        received.starts_with("event: traffic\ndata: {"),
        "the empty opening event first: {received}"
    );
    assert!(received.contains("\"replace\":true"), "it clears the chart");
    let unknown = fixture
        .get("/ui/sse/r/home/network/traffic", &viewer)
        .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "a name is needed");
    Ok(())
}
