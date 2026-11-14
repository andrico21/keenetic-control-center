//! The DHCP page: per-role views and controls, a pool and a static lease applied and read
//! back, a static lease outside every pool refused with its field error, and a router
//! refusal.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};

use crate::{
    row,
    support::{
        outcome::TestResult,
        page::{form, header_text, said, text},
        web::Fixture,
    },
};

/// The pools view.
const PAGE: &str = "/ui/r/home/dhcp";

/// A valid pool on the fixture's home network.
pub(crate) const POOL: [(&str, &str); 8] = [
    ("name", "Pool23"),
    ("begin", "192.0.2.80"),
    ("end", "192.0.2.120"),
    ("gateway", "192.0.2.1"),
    ("dns", "192.0.2.1"),
    ("lease", "3600"),
    ("interface", "Bridge0"),
    ("enabled", "on"),
];

#[tokio::test]
async fn each_role_sees_the_views_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let pools = text(fixture.get(PAGE, &browser).await?).await?;
        for shown in [
            said(Locale::En, keys::WEB_DHCP_TITLE),
            said(Locale::En, keys::WEB_KIT_TABLE_EMPTY),
            "href=\"/ui/r/home/dhcp/bindings\"".to_owned(),
            "href=\"/ui/r/home/dhcp\" aria-current=\"page\"".to_owned(),
        ] {
            assert!(pools.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(
            pools.contains("hx-get=\"/ui/r/home/dhcp/pools/edit\""),
            changes,
            "{account} add pool"
        );
        let bindings = text(fixture.get(&format!("{PAGE}/bindings"), &browser).await?).await?;
        let bound = row(&bindings, "02:00:00:00:10:03").ok_or("binding row")?;
        for shown in [
            "phone-registered",
            "192.0.2.23",
            "Bridge0",
            "bound",
            "1\u{a0}h",
        ] {
            assert!(bound.contains(shown), "{account} misses {shown} in {bound}");
        }
        assert_eq!(
            bound.contains("hx-get=\"/ui/r/home/dhcp/leases/new?mac=02%3A00%3A00%3A00%3A10%3A03&#38;address=192.0.2.23\""),
            changes,
            "{account} make static"
        );
    }
    let viewer = fixture.login("viewer").await?;
    let arp = text(fixture.get(&format!("{PAGE}/arp"), &viewer).await?).await?;
    assert!(arp.contains("reachable"), "ARP states: {arp}");
    let unknown = fixture.get(&format!("{PAGE}/routes"), &viewer).await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown view");
    let refused = fixture
        .post(&format!("{PAGE}/pools/edit"), &viewer, &form(&POOL))
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the route checks too"
    );
    let dialog = fixture.get(&format!("{PAGE}/leases/new"), &viewer).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
    Ok(())
}

#[tokio::test]
async fn a_pool_and_a_static_lease_are_applied_and_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let created = fixture
        .post(&format!("{PAGE}/pools/edit"), &operator, &form(&POOL))
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "pool applied");
    let body = text(created).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"dhcp-region\" hx-swap-oob=\"true\"".to_owned(),
        "192.0.2.80 to 192.0.2.120".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip dhcp pool Pool23"),
        "the router has the pool"
    );
    let editor = text(
        fixture
            .get(&format!("{PAGE}/pools/edit?name=Pool23"), &operator)
            .await?,
    )
    .await?;
    assert!(
        editor.contains("name=\"existing\" value=\"1\"") && editor.contains("value=\"3600\""),
        "the editor starts from the pool: {editor}"
    );
    let lease = form(&[("mac", "02:00:00:00:10:aa"), ("address", "192.0.2.99")]);
    let added = fixture
        .post(&format!("{PAGE}/leases/new"), &operator, &lease)
        .await?;
    assert_eq!(added.status(), StatusCode::OK, "lease applied");
    let read_back = text(added).await?;
    let reserved = row(&read_back, "02:00:00:00:10:aa").ok_or("lease read back")?;
    assert!(reserved.contains("192.0.2.99"), "the address: {reserved}");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.dhcp_static_lease" && entry.outcome == "success"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_static_lease_outside_every_pool_shows_the_field_error() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    let typo = form(&[("mac", "02:00:00:00:10"), ("address", "192.0.2.99")]);
    let refused = fixture
        .post(&format!("{PAGE}/leases/new"), &operator, &typo)
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "MAC error"
    );
    assert!(
        text(refused)
            .await?
            .contains(&said(Locale::En, keys::WEB_DHCP_ERROR_MAC)),
        "the MAC rule"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let running = fixture.handle().running_config_text();
    let outside = form(&[("mac", "02:00:00:00:10:aa"), ("address", "198.51.100.25")]);
    let response = fixture
        .post(&format!("{PAGE}/leases/new"), &operator, &outside)
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
        body.contains(&said(Locale::En, keys::WEB_DHCP_ERROR_OUTSIDE)),
        "the pool rule: {body}"
    );
    assert!(
        body.contains("value=\"198.51.100.25\""),
        "the value as typed"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "no lease written"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.dhcp_static_lease"
                && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}
