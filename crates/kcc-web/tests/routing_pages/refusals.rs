//! Changes the router refuses, and firewall values refused before anything is sent.
//!
//! A route, a port forward or a firewall rule the router refuses shows the router's words,
//! changes nothing and is audited as a router error; a malformed firewall rule is refused
//! with its field error; a forward or a route the domain cannot plan is answered in the
//! outcome region and audited with the plan's own reason.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::json;

use crate::{
    post,
    support::{
        outcome::TestResult,
        page::{en, form, header_text},
        refusal::{Refusal, router_refusals},
        web::Fixture,
    },
};

/// A route, a port forward and a firewall rule the router refuses show its words.
#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let route = form(&[
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ]);
    let forward = form(&[
        ("protocol", "tcp"),
        ("interface", "ISP"),
        ("port", "8443"),
        ("target", "192.0.2.44"),
        ("to_port", "443"),
    ]);
    let rule = form(&[
        ("list", "WebAcl"),
        ("action", "deny"),
        ("protocol", "udp"),
        ("source", "192.0.2.0"),
        ("source_mask", "255.255.255.0"),
        ("destination", "203.0.113.5"),
        ("destination_mask", "255.255.255.255"),
    ]);
    let row = |action, refused, post| Refusal {
        action,
        refused,
        account: "admin",
        post,
        unsaid: refused,
        absent: &[],
        unchanged: true,
    };
    router_refusals(&[
        row(
            "web.routing_route_add",
            "ip route 198.51.100.0",
            ("/ui/r/home/routing/route/new?family=ipv4", &route),
        ),
        row(
            "web.nat_forward_add",
            "ip static tcp ISP 8443",
            ("/ui/r/home/nat/forward/new", &forward),
        ),
        row(
            "web.firewall_rule_add",
            "access-list WebAcl deny",
            ("/ui/r/home/firewall/rule/new", &rule),
        ),
    ])
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
    assert!(mask.contains(&en(keys::WEB_ROUTING_ERROR_MASK)), "{mask}");
    assert!(mask.contains("value=\"255.0.255.0\""), "the value as typed");
    let ported = rule("icmp", "255.255.255.255", "443");
    let port = post(&fixture, &admin, (new, &ported), invalid).await?;
    assert!(port.contains(&en(keys::WEB_NAT_ERROR_PORTS)), "{port}");
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    assert!(
        fixture.audited("web.firewall_rule_add", "validation_failed")?,
        "audited"
    );
    Ok(())
}

/// Posts `fields` to `path` on a router the domain cannot plan the change for.
///
/// The router's only interface has a name the catalog refuses; the test checks the answer,
/// the router's configuration and the audit record of `action`.
async fn unplanned((path, fields): (&str, &[(&str, &str)]), action: &str) -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .show_fixture(
            "interface",
            json!({ "Uplink One": { "id": "Uplink One", "type": "GigabitEthernet" } }),
        )
        .build()?;
    let fixture = Fixture::with_router(fake).await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let answer = fixture.post(path, &admin, &form(fields)).await?;
    assert_eq!(
        answer.status(),
        StatusCode::OK,
        "{path}: the outcome region"
    );
    assert_eq!(
        header_text(&answer, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "{path}: the dialog closes"
    );
    assert_eq!(
        header_text(&answer, "hx-retarget"),
        None,
        "{path}: no field error in the dialog"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "{path} changed nothing"
    );
    assert!(
        fixture.audited(action, "validation_failed")?,
        "{action} audited with the catalog's findings"
    );
    Ok(())
}

#[tokio::test]
async fn a_port_forward_the_domain_cannot_plan_is_answered_in_the_outcome_region() -> TestResult {
    let fields = [
        ("protocol", "tcp"),
        ("interface", "Uplink One"),
        ("port", "8443"),
        ("target", "192.0.2.44"),
        ("to_port", "443"),
    ];
    unplanned(
        ("/ui/r/home/nat/forward/new", &fields),
        "web.nat_forward_add",
    )
    .await
}

#[tokio::test]
async fn a_route_the_domain_cannot_plan_is_answered_in_the_outcome_region() -> TestResult {
    let fields = [
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("interface", "Uplink One"),
    ];
    unplanned(
        ("/ui/r/home/routing/route/new?family=ipv4", &fields),
        "web.routing_route_add",
    )
    .await
}
