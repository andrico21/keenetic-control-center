//! Routing, firewall and port forwarding dialogs and changes whose router read fails: the
//! failure is shown, and no list read as empty lets a change through.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::FaultInjection;

use crate::support::{
    outcome::TestResult,
    page::{en_with, form, text},
    web::Fixture,
};

/// W3-05: a dialog whose router read fails shows the failure instead of a form whose
/// choices are empty, which would refuse every value as "not a choice".
#[tokio::test]
async fn a_dialog_whose_read_fails_shows_the_failure() -> TestResult {
    for (path, read) in [
        ("/ui/r/home/routing/route/new?family=ipv4", "show/interface"),
        (
            "/ui/r/home/routing/policy/permit?name=Policy0",
            "show/interface",
        ),
        ("/ui/r/home/firewall/bind", "show/interface"),
        ("/ui/r/home/nat/forward/new", "show/interface"),
        ("/ui/r/home/nat/interface/new", "show/interface"),
    ] {
        let faults = FaultInjection::default()
            .show_requires_post("show/interface")
            .fail_read_matching(read, 100);
        let fixture = Fixture::with_faults(faults).await?;
        let admin = fixture.login("admin").await?;
        let answer = text(fixture.get(path, &admin).await?).await?;
        assert!(
            answer.contains(&en_with(keys::WEB_KIT_HTTP_ERROR, &[("status", "500")])),
            "{path}: {answer}"
        );
        assert!(!answer.contains("<form"), "{path} offers no form: {answer}");
    }
    Ok(())
}

/// W3-05: the schedule dialog of a firewall rule whose schedules read fails shows the
/// failure instead of a list offering no schedule.
#[tokio::test]
async fn a_schedule_dialog_whose_read_fails_shows_the_failure() -> TestResult {
    let faults = FaultInjection::default().fail_read_matching("show/schedule", 100);
    let fixture = Fixture::with_faults(faults).await?;
    let admin = fixture.login("admin").await?;
    let rule = [
        ("list", "WebAcl"),
        ("action", "deny"),
        ("protocol", "ip"),
        ("source", "192.0.2.5"),
        ("source_mask", "255.255.255.255"),
        ("destination", "198.51.100.5"),
        ("destination_mask", "255.255.255.255"),
    ];
    let created = fixture
        .post("/ui/r/home/firewall/rule/new", &admin, &form(&rule))
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "the rule");
    let path = "/ui/r/home/firewall/rule/schedule?list=WebAcl&index=0&rule=deny+ip+192.0.2.5+255.255.255.255+198.51.100.5+255.255.255.255";
    let answer = text(fixture.get(path, &admin).await?).await?;
    assert!(
        answer.contains(&en_with(keys::WEB_KIT_HTTP_ERROR, &[("status", "500")])),
        "{answer}"
    );
    assert!(!answer.contains("<form"), "no form: {answer}");
    Ok(())
}

/// W3-05: a route whose duplicate check cannot read the routing table is not added.
#[tokio::test]
async fn a_route_is_not_added_when_the_table_cannot_be_read() -> TestResult {
    let faults = FaultInjection::default().fail_read_matching("show/ip/route", 1);
    let fixture = Fixture::with_faults(faults).await?;
    let admin = fixture.login("admin").await?;
    let fields = [
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ];
    let path = "/ui/r/home/routing/route/new?family=ipv4";
    let response = fixture.post(path, &admin, &form(&fields)).await?;
    assert_ne!(response.status(), StatusCode::NOT_FOUND, "answered");
    assert_eq!(fixture.outcomes("web.routing_route_add")?, ["unreachable"]);
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("ip route 198.51.100.0"),
        "nothing was added"
    );
    Ok(())
}

/// W3-05: a policy change whose policies read fails is audited `unreachable`, not `gone`,
/// and a new policy is not created when the existing names cannot be read.
#[tokio::test]
async fn a_policy_read_failure_is_unreachable_not_gone() -> TestResult {
    let faults = FaultInjection::default().fail_read_matching("policy", 100);
    let fixture = Fixture::with_faults(faults).await?;
    let admin = fixture.login("admin").await?;
    let multipath = "/ui/r/home/routing/policy/multipath?name=Policy0&value=on";
    let _answered = fixture.post(multipath, &admin, &form(&[])).await?;
    assert_eq!(
        fixture.outcomes("web.routing_policy_multipath")?,
        ["unreachable"]
    );
    let new = "/ui/r/home/routing/policy/new";
    let _created = fixture
        .post(new, &admin, &form(&[("name", "Policy0")]))
        .await?;
    assert_eq!(
        fixture.outcomes("web.routing_policy_create")?,
        ["unreachable"]
    );
    assert!(
        fixture
            .handle()
            .request_log()
            .iter()
            .all(|record| record.command().is_none()),
        "nothing was sent"
    );
    Ok(())
}
