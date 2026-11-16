//! The segments page: per-role controls, the wizard's review and a segment created, details
//! refused before anything is written, and a failed step rolled back and named.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};

use crate::support::{
    asked::{asks_first, runs_in_timer},
    outcome::TestResult,
    page::{form, header_text, html, router_said, said, text},
    web::Fixture,
};

/// The page under test.
const PAGE: &str = "/ui/r/home/segments";

/// A segment beside the fixture's home network, with one trunk port and a Wi-Fi network.
const SEGMENT: [(&str, &str); 9] = [
    ("id", "23"),
    ("vlan", "23"),
    ("address", "198.51.100.1"),
    ("mask", "255.255.255.0"),
    ("begin", "198.51.100.10"),
    ("end", "198.51.100.50"),
    ("port", "GigabitEthernet0/1"),
    ("access_point", "WifiMaster0/AccessPoint1"),
    ("policy", ""),
];

/// `SEGMENT` with `name` set to `value`.
fn changed(name: &str, value: &'static str) -> Vec<(&'static str, &'static str)> {
    SEGMENT
        .iter()
        .map(|&(field, current)| (field, if field == name { value } else { current }))
        .collect()
}

fn confirmed_segment() -> Vec<(&'static str, &'static str)> {
    SEGMENT
        .into_iter()
        .chain([("confirm", "yes"), ("confirm_name", "home")])
        .collect()
}

#[tokio::test]
async fn each_role_sees_the_page_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let create = "hx-get=\"/ui/r/home/segments/new\"";
    for (account, creates) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        assert!(
            page.contains(&said(Locale::En, keys::WEB_SEGMENTS_EMPTY)),
            "{account} sees the empty list: {page}"
        );
        assert_eq!(page.contains(create), creates, "{account} create");
    }
    let viewer = fixture.login("viewer").await?;
    let dialog = fixture.get(&format!("{PAGE}/new"), &viewer).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no wizard");
    let refused = fixture
        .post(&format!("{PAGE}/create"), &viewer, &form(&SEGMENT))
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the route checks too"
    );
    let operator = fixture.login("operator").await?;
    let details = text(fixture.get(&format!("{PAGE}/new"), &operator).await?).await?;
    for expected in [
        "id=\"segment-id\" name=\"id\" type=\"text\" value=\"2\"",
        "name=\"port\" value=\"GigabitEthernet0/4\"",
        "<option value=\"WifiMaster0/AccessPoint1\">",
    ] {
        assert!(
            details.contains(expected),
            "missing {expected} in {details}"
        );
    }
    Ok(())
}

/// W3-07: a role with router writes makes a management change: asked first, nothing is
/// sent until confirmed, and its own permission authorizes the recovery timer around it.
#[tokio::test]
async fn management_access_point_segment_asks_first_then_is_bracketed_for_writer() -> TestResult {
    let create = format!("{PAGE}/create");
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario),
        )
        .await?;
        let writer = fixture.login("writer").await?;
        let pairs = changed("access_point", "WifiMaster0/AccessPoint0");
        let confirm = asks_first(&fixture, &writer, (&create, &pairs)).await?;
        runs_in_timer(&fixture, &writer, (&confirm, &[]), mode).await?;
    }
    Ok(())
}

/// W3-07: a segment on the port kcc reaches the router through asks first; confirmed, it
/// runs inside the recovery timer.
#[tokio::test]
async fn management_port_segment_asks_first_then_is_bracketed_for_writer() -> TestResult {
    let create = format!("{PAGE}/create");
    let fixture = Fixture::new().await?;
    let writer = fixture.login("writer").await?;
    let confirm = asks_first(&fixture, &writer, (&create, &SEGMENT)).await?;
    runs_in_timer(&fixture, &writer, (&confirm, &[]), "router").await
}

#[tokio::test]
async fn a_segment_is_reviewed_then_created() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let review = fixture
        .post(&format!("{PAGE}/review"), &admin, &form(&SEGMENT))
        .await?;
    assert_eq!(review.status(), StatusCode::OK, "reviewed");
    let steps = text(review).await?;
    for expected in [
        "VLAN subinterface Vlan23 with VLAN ID 23",
        "VLAN 23 tagged on GigabitEthernet0/1",
        "Bridge Bridge23 with address 198.51.100.1/24",
        "DHCP pool Pool23 handing out 198.51.100.10 to 198.51.100.50",
        "Wi-Fi WifiMaster0/AccessPoint1 joins the segment",
    ] {
        assert!(
            steps.contains(&html(expected)),
            "missing {expected} in {steps}"
        );
    }
    assert!(
        steps.contains("hx-post=\"/ui/r/home/segments/create\""),
        "Create sends the details again"
    );
    let created = fixture
        .post(
            &format!("{PAGE}/create"),
            &admin,
            &form(&confirmed_segment()),
        )
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    assert_eq!(
        header_text(&created, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "the wizard closes"
    );
    let body = text(created).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_DONE_UNSAVED)),
        "applied: {body}"
    );
    let running = fixture.handle().running_config_text();
    for line in [
        "interface Bridge23",
        "include WifiMaster0/AccessPoint1",
        "ip dhcp pool Pool23",
        "ip nat Bridge23",
    ] {
        assert!(running.contains(line), "missing {line} in {running}");
    }
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.segments_create" && entry.outcome == "success"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_details_are_refused_before_anything_is_written() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let running = fixture.handle().running_config_text();
    let mut wrong = changed("vlan", "5000");
    wrong.retain(|(field, _)| *field != "begin");
    wrong.push(("begin", "203.0.113.5"));
    let response = fixture
        .post(&format!("{PAGE}/review"), &operator, &form(&wrong))
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field errors"
    );
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the wizard"
    );
    let body = text(response).await?;
    for key in [
        keys::WEB_SEGMENTS_ERROR_VLAN,
        keys::WEB_SEGMENTS_ERROR_RANGE,
    ] {
        assert!(
            body.contains(&said(Locale::En, key)),
            "{} in {body}",
            key.id()
        );
    }
    assert!(body.contains("value=\"5000\""), "the value as typed");
    let overlapping = form(&[
        ("id", "23"),
        ("vlan", "23"),
        ("address", "192.0.2.129"),
        ("mask", "255.255.255.192"),
        ("begin", "192.0.2.130"),
        ("end", "192.0.2.180"),
    ]);
    let refused = text(
        fixture
            .post(&format!("{PAGE}/create"), &operator, &overlapping)
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("name", "Bridge0");
    let overlap = html(&tr(
        Locale::En,
        keys::WEB_SEGMENTS_ERROR_OVERLAP,
        Some(&args),
    ));
    assert!(refused.contains(&overlap), "names the network: {refused}");
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "nothing written"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.segments_create"
                && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_step_is_rolled_back_and_named() -> TestResult {
    let fixture = Fixture::with_faults(
        FaultInjection::default().fail_parse_matching("interface Bridge23", 1),
    )
    .await?;
    let admin = fixture.login("admin").await?;
    let running = fixture.handle().running_config_text();
    let response = fixture
        .post(
            &format!("{PAGE}/create"),
            &admin,
            &form(&confirmed_segment()),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "localized: {body}"
    );
    let list = router_said(&body).ok_or("no router-said list")?;
    assert!(!list.contains("198.51.100.1"), "no request: {list}");
    let mut args = FluentArgs::new();
    args.set("name", "bridge");
    let step = html(&tr(Locale::En, keys::WEB_SEGMENTS_FAILED_STEP, Some(&args)));
    assert!(body.contains(&step), "names the step: {body}");
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "rolled back"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.segments_create" && entry.outcome == "rci_error"),
        "audited"
    );
    Ok(())
}
