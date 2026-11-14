//! The clients page: per-role controls and filters, a client blocked and read back, a
//! name refused before anything is sent, and a router refusal.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_rci::{RciBody, RciPath};
use serde_json::Value;

use crate::{
    dhcp::POOL,
    row,
    support::{
        outcome::TestResult,
        page::{form, header_text, said, text},
        refusal::{Refusal, router_refusals},
        web::{Fixture, ROUTER},
    },
};

/// The page under test.
const PAGE: &str = "/ui/r/home/clients";

/// The fixture's unregistered wired client.
const UNREGISTERED: &str = "02:00:00:00:10:02";

/// `action` on the client `mac`.
fn action(action: &str, mac: &str) -> String {
    format!("{PAGE}/{action}?mac={}", mac.replace(':', "%3A"))
}

#[tokio::test]
async fn each_role_sees_the_clients_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let menu = "popovertarget=\"client-menu-1\"";
    for (account, acts) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_CLIENTS_TITLE),
            "wired-registered".to_owned(),
            "02:00:00:00:10:05".to_owned(),
            "192.0.2.26".to_owned(),
            "WifiMaster1/AccessPoint0".to_owned(),
            "-37\u{a0}dBm".to_owned(),
            said(Locale::En, keys::WEB_CLIENTS_UNREGISTERED),
            "6 of 6".to_owned(),
            "id=\"page-outcome\"".to_owned(),
            "href=\"/ui/r/home/dhcp\"".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(menu), acts, "{account} actions");
    }
    let viewer = fixture.login("viewer").await?;
    let blocked = fixture
        .post(
            &action("access", UNREGISTERED),
            &viewer,
            &form(&[("value", "deny")]),
        )
        .await?;
    assert_eq!(
        blocked.status(),
        StatusCode::FORBIDDEN,
        "the route checks too"
    );
    let dialog = fixture.get(&action("name", UNREGISTERED), &viewer).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
    let missing = fixture.get("/ui/r/cottage/clients", &viewer).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "unknown router");
    let ukrainian = fixture.login("ukrainian").await?;
    let localized = text(fixture.get(PAGE, &ukrainian).await?).await?;
    assert!(
        localized.contains(&said(Locale::Uk, keys::WEB_CLIENTS_FILTER_SEARCH)),
        "the account's language"
    );
    Ok(())
}

#[tokio::test]
async fn filters_narrow_the_table_and_survive_sorting() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let wireless = text(
        fixture
            .get(
                &format!("{PAGE}?state=online&link=wireless&sort=ip&dir=desc"),
                &viewer,
            )
            .await?,
    )
    .await?;
    assert!(
        wireless.contains("4 of 6"),
        "four wireless clients: {wireless}"
    );
    assert!(!wireless.contains("02:00:00:00:10:01"), "no wired client");
    let first = wireless.find("192.0.2.26").ok_or("guest row")?;
    let last = wireless.find("192.0.2.23").ok_or("phone row")?;
    assert!(first < last, "sorted by address, highest first");
    assert!(
        wireless.contains(
            "href=\"/ui/r/home/clients?state=online&#38;link=wireless&#38;sort=name&#38;dir=asc\""
        ),
        "a sort link keeps the filters"
    );
    let searched = text(fixture.get(&format!("{PAGE}?q=10:05"), &viewer).await?).await?;
    assert!(searched.contains("1 of 6"), "one match: {searched}");
    assert!(searched.contains("laptop-registered"), "by MAC");
    let none = text(fixture.get(&format!("{PAGE}?q=nobody"), &viewer).await?).await?;
    assert!(
        none.contains(&said(Locale::En, keys::WEB_KIT_TABLE_NO_MATCH)),
        "says nothing matches"
    );
    Ok(())
}

#[tokio::test]
async fn blocking_a_client_reads_the_row_back_blocked() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let before = text(fixture.get(PAGE, &operator).await?).await?;
    let unregistered = row(&before, UNREGISTERED).ok_or("client row")?;
    assert!(
        !unregistered.contains(&said(Locale::En, keys::WEB_CLIENTS_BLOCKED)),
        "allowed at first: {unregistered}"
    );
    let response = fixture
        .post(
            &action("access", UNREGISTERED),
            &operator,
            &form(&[("value", "deny")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
        "id=\"clients-region\" hx-swap-oob=\"true\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let read_back = row(&body, UNREGISTERED).ok_or("row read back")?;
    assert!(
        read_back.contains(&said(Locale::En, keys::WEB_CLIENTS_BLOCKED)),
        "blocked after read-back: {read_back}"
    );
    assert!(
        !read_back.contains(&said(Locale::En, keys::WEB_CLIENTS_UNREGISTERED)),
        "registered on the way: {read_back}"
    );
    let reloaded = text(fixture.get(PAGE, &operator).await?).await?;
    let shown = row(&reloaded, UNREGISTERED).ok_or("row after reload")?;
    assert!(
        shown.contains(&said(Locale::En, keys::WEB_CLIENTS_ACTION_PERMIT)),
        "the row now offers access back: {shown}"
    );
    let client = fixture.registry().client(ROUTER).await?;
    let RciBody::Json(hotspot) = client
        .show(&RciPath::from_segments(["show", "ip", "hotspot"])?, &())
        .await?
    else {
        return Err("hotspot is not JSON".into());
    };
    let access = hotspot
        .value
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|entry| entry.get("mac").and_then(Value::as_str) == Some(UNREGISTERED))
        })
        .and_then(|entry| entry.get("access"))
        .cloned();
    assert_eq!(access, Some(Value::from("deny")), "the router denies it");
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    let audit = fixture.audit()?;
    let web = audit
        .iter()
        .find(|entry| entry.action == "web.clients_access")
        .ok_or("no web audit")?;
    assert_eq!(web.outcome, "success", "outcome");
    assert!(
        !web.params_redacted.to_string().contains(UNREGISTERED),
        "no MAC in the web audit"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_name_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let dialog = text(
        fixture
            .get(&action("name", UNREGISTERED), &operator)
            .await?,
    )
    .await?;
    assert!(
        dialog.contains("value=\"wired-unregistered\""),
        "the dialog starts from the current name: {dialog}"
    );
    let before = fixture.handle().request_count();
    let response = fixture
        .post(
            &action("name", UNREGISTERED),
            &operator,
            &form(&[("value", "bad name!")]),
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field error"
    );
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_CLIENTS_NAME_ERROR)),
        "the rule: {body}"
    );
    assert!(body.contains("value=\"bad name!\""), "the value as typed");
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.clients_register"
                && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

/// A refused client name and a refused pool show only the router's words.
#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let name = action("name", UNREGISTERED);
    let pool = form(&POOL);
    router_refusals(&[
        Refusal {
            action: "web.clients_register",
            refused: "known host",
            account: "operator",
            post: (&name, "value=office-pc"),
            unsaid: "known host",
            absent: &["clients-region"],
            unchanged: true,
        },
        Refusal {
            action: "web.dhcp_pool",
            refused: "ip dhcp pool",
            account: "operator",
            post: ("/ui/r/home/dhcp/pools/edit", &pool),
            unsaid: "Pool23",
            absent: &["dhcp-region"],
            unchanged: false,
        },
    ])
    .await
}
