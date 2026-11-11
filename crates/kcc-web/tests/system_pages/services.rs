//! Services.
//!
//! Per-role switches, an ordinary service turned on and read back, a management service
//! that asks first and runs inside the fail-safe timer, refusals, and a router refusal.

use std::io::{self, Write as _};

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_rci::RciBody;
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::{Value, json};

use crate::{
    audited, cli_targets, en,
    support::{Fixture, ROUTER, TestResult, header_text, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/services";

/// Stopping every management service preserves the dialog, role gate and both timer edges.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test]
async fn management_service_stops_keep_the_web_bracket_in_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::with_router(fake).await?;
        let admin = fixture.login("admin").await?;
        for name in ["http", "ssh", "telnet"] {
            let toggle = format!("{PAGE}/toggle?name={name}&on=false");
            for role in ["operator", "writer"] {
                let browser = fixture.login(role).await?;
                let before = fixture.handle().request_log().len();
                let denied = fixture.post(&toggle, &browser, "").await?;
                assert_eq!(denied.status(), StatusCode::FORBIDDEN);
                assert!(
                    fixture
                        .handle()
                        .request_log()
                        .iter()
                        .skip(before)
                        .all(|record| record.command().is_none()),
                    "no unauthorized mutation"
                );
            }
            let prompt = fixture.post(&toggle, &admin, "").await?;
            assert_eq!(
                header_text(&prompt, "hx-retarget").as_deref(),
                Some("#dialog-content")
            );
            let before = fixture.handle().request_log().len();
            let response = fixture.post(&toggle, &admin, "confirm=yes").await?;
            assert_eq!(response.status(), StatusCode::OK);
            let commands = fixture
                .handle()
                .request_log()
                .iter()
                .skip(before)
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            let (arm, disarm) = if mode == "router" {
                (
                    "system configuration fail-safe timer reboot 300",
                    "no system configuration fail-safe timer",
                )
            } else {
                ("system reboot 300", "no system reboot")
            };
            assert_eq!(
                commands.first().map(String::as_str),
                Some(arm),
                "{mode} {name}: {commands:?}"
            );
            assert_eq!(
                commands.last().map(String::as_str),
                Some(disarm),
                "{mode} {name}: {commands:?}"
            );
            writeln!(
                io::stderr(),
                "BRACKET Web {mode} service {name} off: dialog; operator/writer 403; arm + disarm"
            )?;
        }
    }
    Ok(())
}

/// A silently ignored typed service write renders its failed field without success.
#[tokio::test]
async fn silent_service_noop_is_a_failed_outcome() -> TestResult {
    let fixture = Fixture::with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
    let operator = fixture.login("operator").await?;
    let body = text(
        fixture
            .post(&format!("{PAGE}/toggle?name=iperf3&on=true"), &operator, "")
            .await?,
    )
    .await?;
    assert!(body.contains("/service"), "failed field missing: {body}");
    assert!(
        !body.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "ignored write reported applied: {body}"
    );
    assert!(
        !fixture
            .audit()?
            .iter()
            .any(|entry| entry.outcome == "applied_unsaved")
    );
    Ok(())
}

/// The services the fake router's running configuration turns on.
async fn configured(fixture: &Fixture) -> TestResult<Vec<String>> {
    let client = fixture.registry().client(ROUTER).await?;
    let RciBody::Json(reply) = client.show_rc(json!({"service": {}})).await? else {
        return Err("show rc service is not JSON".into());
    };
    Ok(reply
        .value
        .pointer("/show/rc/service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|service| service.get("name")?.as_str().map(str::to_owned))
        .collect())
}

#[tokio::test]
async fn each_role_sees_the_services_and_only_its_switches() -> TestResult {
    let fixture = Fixture::new().await?;
    let plain = "hx-post=\"/ui/r/home/system/services/toggle?name=iperf3&#38;on=true\"";
    let management = "hx-post=\"/ui/r/home/system/services/toggle?name=ssh&#38;on=true\"";
    for (account, plain_shown, management_shown) in [
        ("viewer", false, false),
        ("operator", true, false),
        ("admin", true, true),
    ] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            en(keys::WEB_SYSTEM_SERVICES_TITLE),
            ">iperf3<".to_owned(),
            ">ssh<".to_owned(),
            en(keys::WEB_SYSTEM_SERVICES_MANAGEMENT),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(plain), plain_shown, "{account} plain");
        assert_eq!(
            page.contains(management),
            management_shown,
            "{account} management"
        );
    }
    let filtered = text(
        fixture
            .get(&format!("{PAGE}?q=ssh"), &fixture.login("viewer").await?)
            .await?,
    )
    .await?;
    assert!(
        filtered.contains(">ssh<") && !filtered.contains(">iperf3<"),
        "filtered"
    );
    Ok(())
}

#[tokio::test]
async fn an_ordinary_service_is_turned_on_and_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(&format!("{PAGE}/toggle?name=iperf3&on=true"), &operator, "")
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    let body = text(response).await?;
    for expected in [
        en(keys::WEB_KIT_DONE_UNSAVED),
        "id=\"services-region\" aria-labelledby=\"services-title\" hx-swap-oob=\"true\"".to_owned(),
        "hx-post=\"/ui/r/home/system/services/toggle?name=iperf3&#38;on=false\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(configured(&fixture).await?, ["iperf3"], "the router has it");
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    assert!(
        cli_targets(&fixture)?
            .iter()
            .all(|target| target != "system configuration fail-safe timer"),
        "no fail-safe for an ordinary service"
    );
    assert!(
        audited(&fixture, "web.system_service", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn ssh_asks_first_and_runs_inside_the_fail_safe_timer() -> TestResult {
    let fixture = Fixture::new().await?;
    let toggle = format!("{PAGE}/toggle?name=ssh&on=true");
    let operator = fixture.login("operator").await?;
    let denied = fixture.post(&toggle, &operator, "").await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    assert!(
        audited(&fixture, "web.system_service", "forbidden")?,
        "audited"
    );
    let admin = fixture.login("admin").await?;
    let asked = fixture.post(&toggle, &admin, "").await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "dialog"
    );
    let prompt = text(asked).await?;
    assert!(
        prompt.contains(&en(keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE)),
        "explains the timer: {prompt}"
    );
    assert!(configured(&fixture).await?.is_empty(), "nothing yet");
    let body = text(fixture.post(&toggle, &admin, "confirm=yes").await?).await?;
    assert!(body.contains(&en(keys::WEB_KIT_DONE_UNSAVED)), "{body}");
    assert_eq!(configured(&fixture).await?, ["ssh"], "on");
    let fail_safe = cli_targets(&fixture)?
        .into_iter()
        .filter(|target| target == "system configuration fail-safe timer")
        .count();
    assert_eq!(fail_safe, 2, "armed, then disarmed");
    Ok(())
}

#[tokio::test]
async fn unknown_services_and_router_refusals() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("service iperf3", 1))
            .await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    for bad in ["name=teleport&on=true", "name=iperf3&on=maybe"] {
        let response = fixture
            .post(&format!("{PAGE}/toggle?{bad}"), &operator, "")
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let body = text(
        fixture
            .post(&format!("{PAGE}/toggle?name=iperf3&on=true"), &operator, "")
            .await?,
    )
    .await?;
    assert!(body.contains(&en(keys::WEB_KIT_REJECTED)), "{body}");
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    assert!(
        audited(&fixture, "web.system_service", "rci_error")?,
        "audited"
    );
    Ok(())
}
