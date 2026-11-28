//! The Wi-Fi page on the answers a real router gives: a name-keyed `show interface` and
//! the `{"station": [...]}` envelope of `show associations`.

use axum::http::StatusCode;
use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::Value;

use crate::support::{outcome::TestResult, page::text, web::Fixture};

/// The page under test.
const PAGE: &str = "/ui/r/home/wifi";

/// The real-shape `show interface` fixture.
const INTERFACES: &str =
    include_str!("../../../kcc-testkit/fixtures/KN-1811/real-5.1.10/show-interface.json");

/// The real-shape `show associations` fixture.
const ASSOCIATIONS: &str =
    include_str!("../../../kcc-testkit/fixtures/KN-1811/real-5.1.10/show-associations.json");

/// Todo 14: the page lists the radios, access points and connected devices of the
/// real-shape answers, and a device takes its access point's network name, so the filter
/// finds it by that name.
#[tokio::test]
async fn the_page_renders_radios_points_and_devices_of_the_real_answers() -> TestResult {
    let interfaces: Value = serde_json::from_str(INTERFACES)?;
    let associations: Value = serde_json::from_str(ASSOCIATIONS)?;
    let fixture = Fixture::with_router(
        FakeRouter::builder(Profile::default())
            .show_fixture("interface", interfaces)
            .show_fixture("associations", associations)
            .build()?,
    )
    .await?;
    let viewer = fixture.login("viewer").await?;

    let response = fixture.get(PAGE, &viewer).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = text(response).await?;
    for shown in [
        "<th scope=\"row\" class=\"mono\" id=\"radio-1\">WifiMaster0</th>",
        "WifiMaster1",
        "WifiMaster1/AccessPoint1",
        "ssid-2",
        "02:00:00:00:14:01",
        "02:00:00:00:14:03",
        "-37 dBm",
    ] {
        assert!(page.contains(shown), "the page misses {shown}");
    }
    let filtered = text(fixture.get(&format!("{PAGE}?q=ssid-1"), &viewer).await?).await?;
    assert!(filtered.contains("1 of 3"), "the device filter: {filtered}");
    assert!(filtered.contains("02:00:00:00:14:01"));
    Ok(())
}
