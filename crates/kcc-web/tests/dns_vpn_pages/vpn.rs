//! The VPN pages against the fake router.
//!
//! Per-role controls, a WireGuard connection created, switched off and on, given a peer
//! and deleted after its name is typed, a peer refused before anything is sent, and a
//! server change the router refuses.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    form, key, said,
    support::{Fixture, TestResult, header_text, text},
};

/// The connections tab.
const PAGE: &str = "/ui/r/home/vpn";

#[tokio::test]
async fn each_role_sees_the_vpn_pages_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let import = "hx-get=\"/ui/r/home/vpn/form/import\"";
    let service = "hx-post=\"/ui/r/home/vpn/service\"";
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_VPN_TAB_CONNECTIONS),
            said(Locale::En, keys::WEB_VPN_CONNECTIONS_EMPTY),
            "href=\"/ui/r/home/vpn/servers\"".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(import), changes, "{account} import");
        let servers = text(fixture.get(&format!("{PAGE}/servers"), &browser).await?).await?;
        for shown in [
            said(Locale::En, keys::WEB_VPN_SERVER_PPTP),
            said(Locale::En, keys::WEB_VPN_SERVER_IPSEC),
            said(Locale::En, keys::WEB_VPN_ACCESS),
            "href=\"/ui/r/home/system/users\"".to_owned(),
        ] {
            assert!(servers.contains(&shown), "{account} servers miss {shown}");
        }
        assert_eq!(servers.contains(service), changes, "{account} service");
    }
    let viewer = fixture.login("viewer").await?;
    let off = form(&[("tunnel", "Wireguard0"), ("enabled", "off")]);
    let refused = fixture
        .post(&format!("{PAGE}/state"), &viewer, &off)
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the route checks too"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.vpn_state"
                && entry.outcome == "forbidden"
                && entry.actor.id == "viewer"),
        "refusal audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_connection_is_created_switched_and_deleted() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let dialog = text(
        fixture
            .get(&format!("{PAGE}/form/create"), &operator)
            .await?,
    )
    .await?;
    assert!(
        dialog.contains("value=\"Wireguard0\""),
        "the first free name: {dialog}"
    );
    let create = form(&[("name", "Wireguard3"), ("port", "51821")]);
    let created = fixture
        .post(&format!("{PAGE}/form/create"), &operator, &create)
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let body = text(created).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"domain-region\" hx-swap-oob=\"true\"".to_owned(),
        "Wireguard3".to_owned(),
        said(Locale::En, keys::WEB_VPN_TYPE_WIREGUARD),
        "href=\"/ui/r/home/vpn/peers/Wireguard3\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    for (next, state) in [("off", keys::COMMON_DISABLED), ("on", keys::COMMON_ENABLED)] {
        let switch = form(&[("tunnel", "Wireguard3"), ("enabled", next)]);
        let switched = text(
            fixture
                .post(&format!("{PAGE}/state"), &operator, &switch)
                .await?,
        )
        .await?;
        let pill = format!(
            "data-status=\"{}\">{}<",
            if next == "on" { "online" } else { "unknown" },
            said(Locale::En, state)
        );
        assert!(switched.contains(&pill), "{next}: {switched}");
    }
    let asked = text(
        fixture
            .get(&format!("{PAGE}/delete?tunnel=Wireguard3"), &operator)
            .await?,
    )
    .await?;
    assert!(
        asked.contains("name=\"confirm\""),
        "the name to type: {asked}"
    );
    let wrong = form(&[("name", "Wireguard3"), ("confirm", "Wireguard")]);
    let mistyped = fixture
        .post(&format!("{PAGE}/delete"), &operator, &wrong)
        .await?;
    assert_eq!(
        mistyped.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "names are exact"
    );
    let right = form(&[("name", "Wireguard3"), ("confirm", "Wireguard3")]);
    let deleted = fixture
        .post(&format!("{PAGE}/delete"), &operator, &right)
        .await?;
    assert_eq!(
        header_text(&deleted, "hx-retarget").as_deref(),
        Some("#page-outcome"),
        "the outcome lands in the page"
    );
    let gone = text(deleted).await?;
    assert!(
        !gone.contains("vpn/peers/Wireguard3"),
        "the row left: {gone}"
    );
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("Wireguard3"),
        "the router has none"
    );
    Ok(())
}

#[tokio::test]
async fn a_peer_is_added_and_read_back_on_the_peers_page() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let create = form(&[("name", "Wireguard4")]);
    let created = fixture
        .post(&format!("{PAGE}/form/create"), &operator, &create)
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let peer_key = key(1);
    let peer = form(&[
        ("tunnel", "Wireguard4"),
        ("key", &peer_key),
        ("endpoint", "198.51.100.7:51820"),
        ("allowed", "192.0.2.0/24"),
        ("keepalive", "25"),
    ]);
    let added = text(
        fixture
            .post(&format!("{PAGE}/form/peer"), &operator, &peer)
            .await?,
    )
    .await?;
    for expected in [
        peer_key.as_str(),
        "198.51.100.7:51820",
        "192.0.2.0/24",
        "<td>25</td>",
    ] {
        assert!(
            added.contains(expected),
            "peer read back misses {expected}: {added}"
        );
    }
    let peers = text(
        fixture
            .get(&format!("{PAGE}/peers/Wireguard4"), &operator)
            .await?,
    )
    .await?;
    assert!(peers.contains(&peer_key), "the peers page lists it");
    Ok(())
}

#[tokio::test]
async fn an_invalid_peer_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    let peer = form(&[
        ("tunnel", "Wireguard3"),
        ("key", "not a key"),
        ("endpoint", "vpn.example:51820"),
        ("allowed", "::/0"),
    ]);
    let response = fixture
        .post(&format!("{PAGE}/form/peer"), &operator, &peer)
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field errors"
    );
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_VPN_ERROR_KEY),
        said(Locale::En, keys::WEB_VPN_ERROR_ENDPOINT),
        said(Locale::En, keys::WEB_VPN_ERROR_ALLOWED),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    Ok(())
}

#[tokio::test]
async fn a_server_change_the_router_refuses_shows_its_words() -> TestResult {
    let fixture = Fixture::with_faults(
        FaultInjection::default().fail_parse_matching("service sstp-server", 1),
    )
    .await?;
    let operator = fixture.login("operator").await?;
    let on = form(&[("service", "sstp"), ("enabled", "on")]);
    let response = fixture
        .post(&format!("{PAGE}/service"), &operator, &on)
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "localized: {body}"
    );
    assert!(body.contains("router-said__list"), "router said block");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.vpn_service" && entry.outcome == "rci_error"),
        "audited"
    );
    Ok(())
}
