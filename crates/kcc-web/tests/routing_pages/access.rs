//! Who may do what on the routing, port forwarding and firewall pages.
//!
//! A viewer reads every page without a change control and is refused every change; unknown
//! routers are not found, routers outside the role's scope are forbidden; no page or audit
//! record carries a secret.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    audited, get, post, said,
    support::{Fixture, ROUTER, TestResult},
};

/// Every page of the family.
const PAGES: [&str; 11] = [
    "/ui/r/home/routing",
    "/ui/r/home/routing/ipv6",
    "/ui/r/home/routing/table",
    "/ui/r/home/routing/table/ipv6",
    "/ui/r/home/routing/policies",
    "/ui/r/home/nat",
    "/ui/r/home/nat/interfaces",
    "/ui/r/home/nat/sessions",
    "/ui/r/home/firewall",
    "/ui/r/home/firewall/interfaces",
    "/ui/r/home/firewall/upnp",
];

/// Every change, with a body that would be valid for an administrator.
const CHANGES: [(&str, &[(&str, &str)]); 17] = [
    (
        "/ui/r/home/routing/route/new?family=ipv4",
        &[
            ("network", "198.51.100.0"),
            ("mask", "255.255.255.0"),
            ("gateway", "192.0.2.254"),
        ],
    ),
    (
        "/ui/r/home/routing/route/remove?family=ipv4&destination=198.51.100.0&mask=255.255.255.0&gateway=192.0.2.254",
        &[],
    ),
    ("/ui/r/home/routing/policy/new", &[("name", "Policy9")]),
    (
        "/ui/r/home/routing/policy/description?name=Policy0",
        &[("description", "x")],
    ),
    (
        "/ui/r/home/routing/policy/permit?name=Policy0",
        &[("interface", "ISP")],
    ),
    (
        "/ui/r/home/routing/policy/unpermit?name=Policy0&interface=ISP",
        &[],
    ),
    (
        "/ui/r/home/routing/policy/multipath?name=Policy0&value=on",
        &[],
    ),
    (
        "/ui/r/home/routing/policy/delete",
        &[("name", "Policy0"), ("confirm", "Policy0")],
    ),
    (
        "/ui/r/home/nat/forward/new",
        &[("interface", "ISP"), ("target", "192.0.2.44")],
    ),
    (
        "/ui/r/home/nat/forward/remove?interface=ISP&target=192.0.2.44",
        &[],
    ),
    ("/ui/r/home/nat/interface/new", &[("interface", "ISP")]),
    ("/ui/r/home/nat/interface/remove?name=Bridge0", &[]),
    (
        "/ui/r/home/firewall/rule/new",
        &[("list", "WebAcl"), ("action", "permit"), ("protocol", "ip")],
    ),
    (
        "/ui/r/home/firewall/rule/move?list=WebAcl&index=1&rule=x&to=0",
        &[],
    ),
    (
        "/ui/r/home/firewall/rule/state?list=WebAcl&index=0&rule=x&value=off",
        &[],
    ),
    (
        "/ui/r/home/firewall/bind",
        &[
            ("list", "WebAcl"),
            ("interface", "ISP"),
            ("direction", "in"),
        ],
    ),
    (
        "/ui/r/home/firewall/unbind?interface=ISP&list=WebAcl&direction=in",
        &[],
    ),
];

#[tokio::test]
async fn a_viewer_reads_every_page_and_is_refused_every_change() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    for page in PAGES {
        let body = get(&fixture, &viewer, page, StatusCode::OK).await?;
        for control in [
            said(keys::WEB_ROUTING_ADD),
            said(keys::WEB_ROUTING_POLICY_ADD),
            said(keys::WEB_NAT_ADD),
            said(keys::WEB_FIREWALL_ADD),
            said(keys::WEB_FIREWALL_BIND),
            said(keys::WEB_ROUTING_REMOVE),
        ] {
            assert!(!body.contains(&control), "{page} shows {control}");
        }
    }
    let before = fixture.handle().running_config_text();
    for (path, fields) in CHANGES {
        drop(post(&fixture, &viewer, (path, fields), StatusCode::FORBIDDEN).await?);
    }
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    for action in [
        "web.routing_route_add",
        "web.routing_policy_create",
        "web.nat_forward_add",
        "web.firewall_rule_add",
        "web.firewall_bind",
    ] {
        assert!(audited(&fixture, action, "forbidden")?, "{action} audited");
    }
    Ok(())
}

#[tokio::test]
async fn unknown_routers_are_not_found_and_other_scopes_forbidden() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    for path in [
        "/ui/r/nope/routing",
        "/ui/r/Bad!/nat",
        "/ui/r/nope/firewall",
    ] {
        drop(get(&fixture, &admin, path, StatusCode::NOT_FOUND).await?);
    }
    let outsider = fixture.login("outsider").await?;
    for path in [
        "/ui/r/lab-1/routing",
        "/ui/r/lab-1/nat",
        "/ui/r/lab-1/firewall",
    ] {
        drop(get(&fixture, &outsider, path, StatusCode::NOT_FOUND).await?);
    }
    for path in PAGES {
        drop(get(&fixture, &outsider, path, StatusCode::FORBIDDEN).await?);
    }
    drop(
        post(
            &fixture,
            &outsider,
            ("/ui/r/home/nat/interface/new", &[("interface", "ISP")]),
            StatusCode::FORBIDDEN,
        )
        .await?,
    );
    Ok(())
}

#[tokio::test]
async fn no_page_or_audit_record_carries_a_secret() -> TestResult {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    let secret = "plain-text-psk-for-t38";
    drop(
        client
            .parse(&format!(
                "interface WifiMaster0/AccessPoint0 authentication wpa-psk {secret}"
            ))
            .await?,
    );
    drop(client.parse("access-list WebAcl permit tcp 192.0.2.10 255.255.255.255 198.51.100.20 255.255.255.255").await?);
    let admin = fixture.login("admin").await?;
    let added = post(
        &fixture,
        &admin,
        (
            "/ui/r/home/routing/route/new?family=ipv4",
            &[
                ("network", "198.51.100.0"),
                ("mask", "255.255.255.0"),
                ("gateway", "192.0.2.254"),
            ],
        ),
        StatusCode::OK,
    )
    .await?;
    let mut shown = vec![added];
    for page in PAGES {
        shown.push(get(&fixture, &admin, page, StatusCode::OK).await?);
    }
    for body in &shown {
        assert!(!body.contains(secret), "no plain secret");
        assert!(!body.contains("ns3"), "no encoded secret");
        assert!(!body.contains("password"), "no password line");
    }
    assert!(
        shown.iter().any(|body| body.contains("WebAcl")),
        "the firewall page read the configuration"
    );
    let records = fixture.audit()?;
    let web: Vec<_> = records
        .iter()
        .filter(|entry| entry.action.starts_with("web."))
        .map(|entry| &entry.params_redacted)
        .collect();
    let audit = serde_json::to_string(&web)?;
    assert!(!audit.contains("198.51.100.0"), "field names only: {audit}");
    assert!(!audit.contains(secret), "no secret in the audit log");
    Ok(())
}
