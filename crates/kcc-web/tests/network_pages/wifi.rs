//! The Wi-Fi page.
//!
//! What each role sees, the settings dialogs and what they offer, a network name read back
//! with the unsaved badge, a network name refused before anything is sent, a router
//! refusal in the router's own words, and the hidden-name switch.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;
use serde_json::Value;

use crate::{
    form, interface, said,
    support::{Fixture, TestResult, header_text, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/wifi";

/// The 5 GHz access point, as a query value.
const POINT: &str = "WifiMaster1%2FAccessPoint0";

#[tokio::test]
async fn each_role_sees_radios_points_and_devices() -> TestResult {
    let fixture = Fixture::new().await?;
    let disable =
        format!("hx-post=\"/ui/r/home/wifi/toggle?name={POINT}&#38;setting=enabled&#38;value=no\"");
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_WIFI_TITLE),
            "<th scope=\"row\" class=\"mono\" id=\"radio-1\">WifiMaster0</th>".to_owned(),
            "ssid-5".to_owned(),
            "WifiMaster1/AccessPoint0".to_owned(),
            "02:00:00:00:10:05".to_owned(),
            "-37 dBm".to_owned(),
            format!("hx-get=\"/ui/r/home/wifi/settings?name={POINT}\""),
            said(Locale::En, keys::WEB_INTERNET_NOT_SET),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(&disable), changes, "{account} switches");
        let strongest = page.find("-37 dBm").ok_or("no strongest device")?;
        let weakest = page.find("-66 dBm").ok_or("no weakest device")?;
        assert!(strongest < weakest, "{account}: strongest signal first");
    }
    let viewer = fixture.login("viewer").await?;
    let refused = fixture
        .post(
            &format!("{PAGE}/toggle?name={POINT}&setting=enabled&value=no"),
            &viewer,
            "",
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "the route checks");
    let filtered = text(
        fixture
            .get(&format!("{PAGE}?q=ssid-guest"), &viewer)
            .await?,
    )
    .await?;
    assert!(filtered.contains("1 of 4"), "the device filter: {filtered}");
    Ok(())
}

#[tokio::test]
async fn the_settings_dialogs_offer_the_routers_own_choices() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let read_only = text(
        fixture
            .get(&format!("{PAGE}/settings?name={POINT}"), &viewer)
            .await?,
    )
    .await?;
    assert!(
        read_only.contains("ssid-5"),
        "the access point: {read_only}"
    );
    assert!(!read_only.contains("wifi/edit/"), "viewer: no Edit");
    let operator = fixture.login("operator").await?;
    let point = text(
        fixture
            .get(&format!("{PAGE}/settings?name={POINT}"), &operator)
            .await?,
    )
    .await?;
    for control in [
        format!("hx-get=\"/ui/r/home/wifi/edit/ssid?name={POINT}\""),
        format!("hx-get=\"/ui/r/home/wifi/edit/schedule?name={POINT}\""),
        format!("hx-post=\"/ui/r/home/wifi/toggle?name={POINT}&#38;setting=hidden&#38;value=yes\""),
    ] {
        assert!(point.contains(&control), "operator misses {control}");
    }
    let radio = text(
        fixture
            .get(&format!("{PAGE}/settings?name=WifiMaster1"), &operator)
            .await?,
    )
    .await?;
    assert!(
        radio.contains("hx-get=\"/ui/r/home/wifi/edit/width?name=WifiMaster1\""),
        "the radio's settings: {radio}"
    );
    let schedule = text(
        fixture
            .get(&format!("{PAGE}/edit/schedule?name={POINT}"), &operator)
            .await?,
    )
    .await?;
    assert!(
        schedule.contains("<option value=\"Schedule0\">Schedule0</option>"),
        "the router's schedules: {schedule}"
    );
    let width = text(
        fixture
            .get(&format!("{PAGE}/edit/width?name=WifiMaster1"), &operator)
            .await?,
    )
    .await?;
    assert!(
        width.contains("<option value=\"40-above\">40-above</option>"),
        "the catalog's widths: {width}"
    );
    Ok(())
}

#[tokio::test]
async fn a_network_name_is_read_back_with_the_unsaved_badge() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            &format!("{PAGE}/edit/ssid?name={POINT}"),
            &operator,
            &form(&[("value", "Upstairs")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    assert_eq!(
        header_text(&response, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "the dialog closes"
    );
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
        "id=\"net-region\" hx-swap-oob=\"true\"".to_owned(),
        "Upstairs".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let read_back = interface(&fixture, "WifiMaster1/AccessPoint0").await?;
    assert_eq!(
        read_back.get("ssid").and_then(Value::as_str),
        Some("Upstairs"),
        "the router has it"
    );
    assert!(
        !fixture
            .handle()
            .request_log()
            .iter()
            .any(|record| record.path().contains("AccessPoint")),
        "names never reach a router path"
    );
    let hidden = fixture
        .post(
            &format!("{PAGE}/toggle?name={POINT}&setting=hidden&value=yes"),
            &operator,
            "",
        )
        .await?;
    assert_eq!(hidden.status(), StatusCode::OK, "hidden");
    assert!(
        fixture.handle().running_config_text().contains("hide-ssid"),
        "the router hides the name"
    );
    Ok(())
}

#[tokio::test]
async fn a_long_network_name_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    let long = "x".repeat(33);
    let response = fixture
        .post(
            &format!("{PAGE}/edit/ssid?name={POINT}"),
            &operator,
            &form(&[("value", &long)]),
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field error"
    );
    let body = text(response).await?;
    let rule = said(Locale::En, keys::WEB_WIFI_SSID_ERROR);
    assert!(
        body.contains(&format!(
            "<p class=\"field__error\" id=\"net-value-error\">{rule}</p>"
        )),
        "the server's message: {body}"
    );
    assert!(
        body.contains(&format!(
            "required maxlength=\"32\" data-kcc-invalid=\"{rule}\""
        )),
        "the same rule for the browser's check"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wifi_ssid" && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("ssid", 1)).await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            &format!("{PAGE}/edit/ssid?name={POINT}"),
            &operator,
            &form(&[("value", "Upstairs")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "localized: {body}"
    );
    let said_block = body
        .split_once("<ul class=\"router-said__list\">")
        .and_then(|(_, tail)| tail.split_once("</ul>"))
        .map(|(list, _)| list.to_owned())
        .ok_or("no router-said list")?;
    assert!(said_block.contains("<li>"), "the router's message");
    assert!(
        !said_block.contains("Upstairs"),
        "no request body: {said_block}"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wifi_ssid" && entry.outcome == "rci_error"),
        "audited"
    );
    Ok(())
}
