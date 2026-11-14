//! The DNS tabs: per-role controls, servers added over HTTPS and TLS and read back, a
//! record refused before anything is sent, and a router refusal in the router's words.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_rci::{RciBody, RciPath};
use serde_json::Value;

use crate::support::{
    outcome::TestResult,
    page::{form, header_text, said, text},
    refusal::{Refusal, router_refusals},
    web::{Fixture, ROUTER},
};

/// The DNS page under test.
const PAGE: &str = "/ui/r/home/dns";

/// `show dns-proxy` on the fake router.
async fn dns_proxy(fixture: &Fixture) -> TestResult<Value> {
    let client = fixture.registry().client(ROUTER).await?;
    match client
        .show(&RciPath::from_segments(["show", "dns-proxy"])?, &())
        .await?
    {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err("show dns-proxy is not JSON".into()),
    }
}

#[tokio::test]
async fn each_role_sees_the_tabs_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let add = "hx-get=\"/ui/r/home/dns/form/server\"";
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_DNS_TAB_SERVERS),
            said(Locale::En, keys::WEB_DNS_PROTOCOL_PLAIN),
            "192.0.2.53".to_owned(),
            "href=\"/ui/r/home/dns/records\"".to_owned(),
            "id=\"page-outcome\"".to_owned(),
            "<option value=\"home\" selected>".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(add), changes, "{account} add");
        for tab in ["filtering", "records", "lists", "routes"] {
            let other = fixture.get(&format!("{PAGE}/{tab}"), &browser).await?;
            assert_eq!(other.status(), StatusCode::OK, "{account} {tab}");
        }
    }
    let viewer = fixture.login("viewer").await?;
    let record = form(&[("domain", "nas.home"), ("address", "192.0.2.10")]);
    let refused = fixture
        .post(&format!("{PAGE}/form/record"), &viewer, &record)
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the route checks too"
    );
    let dialog = fixture.get(&format!("{PAGE}/form/record"), &viewer).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
    for missing in ["/ui/r/cottage/dns", "/ui/r/home/dns/zones"] {
        let response = fixture.get(missing, &viewer).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let ukrainian = fixture.login("ukrainian").await?;
    let localized = text(fixture.get(PAGE, &ukrainian).await?).await?;
    assert!(
        localized.contains(&said(Locale::Uk, keys::WEB_DNS_TAB_SERVERS)),
        "the account's language"
    );
    Ok(())
}

#[tokio::test]
async fn servers_are_added_and_read_back_with_the_unsaved_badge() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let url = "https://dns.fixture.invalid/dns-query";
    let https = form(&[("kind", "https"), ("url", url), ("format", "")]);
    let response = fixture
        .post(&format!("{PAGE}/form/server"), &operator, &https)
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
        "id=\"domain-region\" hx-swap-oob=\"true\"".to_owned(),
        said(Locale::En, keys::WEB_DNS_PROTOCOL_HTTPS),
        url.to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let tls = form(&[
        ("kind", "tls"),
        ("address", "9.9.9.9"),
        ("port", "853"),
        ("sni", "dns.quad9.net"),
    ]);
    let second = text(
        fixture
            .post(&format!("{PAGE}/form/server"), &operator, &tls)
            .await?,
    )
    .await?;
    assert!(
        second.contains("853 sni dns.quad9.net"),
        "the TLS server's options read back: {second}"
    );
    let proxy = dns_proxy(&fixture).await?;
    assert_eq!(
        proxy.pointer("/https/upstream/0/0").and_then(Value::as_str),
        Some(url),
        "the router has the HTTPS server"
    );
    assert_eq!(
        proxy.pointer("/tls/upstream/0/0").and_then(Value::as_str),
        Some("9.9.9.9"),
        "and the TLS one"
    );
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    let audit = fixture.audit()?;
    let web = audit
        .iter()
        .filter(|entry| entry.action == "web.dns_server" && entry.outcome == "success")
        .count();
    assert_eq!(web, 2, "both audited by the page");
    assert!(
        audit.iter().any(|entry| entry.action == "router.change_cli"
            && entry.target.as_deref() == Some("dns-proxy tls upstream")),
        "the change workflow's own entry"
    );
    assert!(
        audit
            .iter()
            .all(|entry| !entry.params_redacted.to_string().contains("quad9")),
        "field names only"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_record_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(&format!("{PAGE}/records"), &operator).await?);
    let before = fixture.handle().request_count();
    let record = form(&[("domain", "nas home;reboot"), ("address", "192.0.2.300")]);
    let response = fixture
        .post(&format!("{PAGE}/form/record"), &operator, &record)
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field errors"
    );
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_DNS_ERROR_DOMAIN),
        said(Locale::En, keys::WEB_DNS_ERROR_ADDRESS),
        "value=\"nas home;reboot\"".to_owned(),
        "aria-invalid=\"true\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.dns_record" && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let record = form(&[("domain", "nas.home"), ("address", "192.0.2.10")]);
    router_refusals(&[Refusal {
        action: "web.dns_record",
        refused: "ip host",
        account: "operator",
        post: (&format!("{PAGE}/form/record"), &record),
        unsaid: "nas.home",
        absent: &["unsaved-badge"],
        unchanged: true,
    }])
    .await
}

#[tokio::test]
async fn a_route_by_domain_list_goes_through_the_change_workflow() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let route = form(&[("list", "video"), ("interface", "Wireguard0")]);
    let response = fixture
        .post(&format!("{PAGE}/form/route"), &operator, &route)
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    // The fake router has no DNS routes, so it refuses the catalog-valid line.
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "the outcome in the page: {body}"
    );
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "web.dns_route" && entry.outcome == "rci_error"),
        "the page's record"
    );
    let invalid = form(&[("list", "video list"), ("interface", "Wireguard0")]);
    let refused = fixture
        .post(&format!("{PAGE}/form/route"), &operator, &invalid)
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "one token per value"
    );
    Ok(())
}
