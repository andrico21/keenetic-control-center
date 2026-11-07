//! Changes the router refuses, and firewall values refused before anything is sent.
//!
//! A route, a port forward or a firewall rule the router refuses shows the router's words,
//! changes nothing and is audited as a router error; a malformed firewall rule is refused
//! with its field error.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::FaultInjection;

use crate::{
    audited, post, said,
    support::{Fixture, TestResult},
};

/// What the fake router answers a line it was told to refuse.
const REFUSAL: &str = "injected parser failure.";

/// Posts `fields` to `path` on a router that refuses the first CLI line containing `line`,
/// and checks the answer, the router's configuration and the audit record of `action`.
async fn refused(line: &str, (path, fields): (&str, &[(&str, &str)]), action: &str) -> TestResult {
    let faults = FaultInjection::default().fail_parse_matching(line, 1);
    let fixture = Fixture::with_faults(faults).await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let answer = post(&fixture, &admin, (path, fields), StatusCode::OK).await?;
    assert!(
        answer.contains(&said(keys::WEB_KIT_REJECTED)),
        "{path}: {answer}"
    );
    assert!(answer.contains(REFUSAL), "the router's words: {answer}");
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "{path} changed nothing"
    );
    assert!(audited(&fixture, action, "rci_error")?, "{action} audited");
    Ok(())
}

#[tokio::test]
async fn a_route_the_router_refuses_shows_what_the_router_said() -> TestResult {
    let path = "/ui/r/home/routing/route/new?family=ipv4";
    let fields = [
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ];
    refused(
        "ip route 198.51.100.0",
        (path, &fields),
        "web.routing_route_add",
    )
    .await
}

#[tokio::test]
async fn a_port_forward_the_router_refuses_shows_what_the_router_said() -> TestResult {
    let path = "/ui/r/home/nat/forward/new";
    let fields = [
        ("protocol", "tcp"),
        ("interface", "ISP"),
        ("port", "8443"),
        ("target", "192.0.2.44"),
        ("to_port", "443"),
    ];
    refused(
        "ip static tcp ISP 8443",
        (path, &fields),
        "web.nat_forward_add",
    )
    .await
}

#[tokio::test]
async fn a_firewall_rule_the_router_refuses_shows_what_the_router_said() -> TestResult {
    let path = "/ui/r/home/firewall/rule/new";
    let fields = [
        ("list", "WebAcl"),
        ("action", "deny"),
        ("protocol", "udp"),
        ("source", "192.0.2.0"),
        ("source_mask", "255.255.255.0"),
        ("destination", "203.0.113.5"),
        ("destination_mask", "255.255.255.255"),
    ];
    refused(
        "access-list WebAcl deny",
        (path, &fields),
        "web.firewall_rule_add",
    )
    .await
}

#[tokio::test]
async fn a_malformed_firewall_rule_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let rule = |protocol, source_mask, port| {
        [
            ("list", "WebAcl"),
            ("action", "permit"),
            ("protocol", protocol),
            ("source", "192.0.2.10"),
            ("source_mask", source_mask),
            ("destination", "198.51.100.20"),
            ("destination_mask", "255.255.255.255"),
            ("destination_port", port),
        ]
    };
    let new = "/ui/r/home/firewall/rule/new";
    let invalid = StatusCode::UNPROCESSABLE_ENTITY;
    let gapped = rule("tcp", "255.0.255.0", "443");
    let mask = post(&fixture, &admin, (new, &gapped), invalid).await?;
    assert!(mask.contains(&said(keys::WEB_ROUTING_ERROR_MASK)), "{mask}");
    assert!(mask.contains("value=\"255.0.255.0\""), "the value as typed");
    let ported = rule("icmp", "255.255.255.255", "443");
    let port = post(&fixture, &admin, (new, &ported), invalid).await?;
    assert!(port.contains(&said(keys::WEB_NAT_ERROR_PORTS)), "{port}");
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    assert!(
        audited(&fixture, "web.firewall_rule_add", "validation_failed")?,
        "audited"
    );
    Ok(())
}
