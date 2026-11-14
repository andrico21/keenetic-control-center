//! A Web management change: who may open its bracket, and what a failed bracket says about
//! the recovery timer.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the recovery contract"
)]
use axum::http::StatusCode;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
    web::Fixture,
};

#[path = "bracket_batch.rs"]
mod batch;
#[path = "bracket_budget.rs"]
mod budget;
#[path = "bracket_dead_audit.rs"]
mod dead_audit;
#[path = "bracket_mode.rs"]
mod mode;
#[path = "bracket_ordinary.rs"]
mod ordinary;

/// The fixture over a fake router reporting `mode` with `faults`.
// NOT cancel-safe: setup creates router and application tasks.
pub(crate) async fn fixture(mode: &str, faults: FaultInjection) -> TestResult<Fixture> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    Fixture::with_router(
        FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?
            .with_migration(scenario),
    )
    .await
}

/// The parser lines the fake received.
pub(crate) fn commands(fixture: &Fixture) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .iter()
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// The arm and disarm lines of the recovery of `mode`.
pub(crate) fn edges(mode: &str) -> [&'static str; 2] {
    if mode == "router" {
        [
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        ]
    } else {
        ["system reboot 300", "no system reboot"]
    }
}

/// The keys that say the timer may still be armed.
const ARMED_KEYS: [MessageKey; 3] = [
    keys::MANAGEMENT_NOT_SENT_ARMED,
    keys::MANAGEMENT_DISARM_FAILED,
    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
];

/// A raw role without ordinary write permission closes its management bracket.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn management_bracket_without_write_permission() -> TestResult {
    let fixture = fixture("router", FaultInjection::default()).await?;
    let browser = fixture.login("rawdes").await?;
    let request = form(&[
        ("method", "POST"),
        ("path", "ip http port"),
        ("body", r#"{"port":8082}"#),
        ("confirm", "yes"),
    ]);
    let response = fixture
        .post("/ui/r/home/console/rci/send", &browser, &request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let sent = commands(&fixture);
    assert_eq!(
        sent.first().map(String::as_str),
        Some(edges("router")[0]),
        "{sent:?}"
    );
    assert_eq!(
        sent.last().map(String::as_str),
        Some(edges("router")[1]),
        "{sent:?}"
    );
    Ok(())
}

/// Every failed bracket shows the message of its fate and flags its audit entry when the
/// timer may be armed; a refusal whose disarm closed the timer keeps the router's words.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn bracket_failure_matrix_retains_recovery() -> TestResult {
    let timer = "system configuration fail-safe timer";
    let port = "ip http port 8430";
    for (faults, line, key, armed) in [
        (
            FaultInjection::default().disconnect_after_parse("ip http port".to_owned()),
            port,
            Some(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED),
            true,
        ),
        (
            FaultInjection::default().fail_parse_matching("no system", 1),
            port,
            Some(keys::MANAGEMENT_DISARM_FAILED),
            true,
        ),
        (
            FaultInjection::default().fail_parse_matching(timer, 2),
            port,
            Some(keys::MANAGEMENT_NOT_SENT_ARMED),
            true,
        ),
        (
            FaultInjection::default().fail_parse_matching(timer, 1),
            port,
            Some(keys::MANAGEMENT_NOT_APPLIED),
            false,
        ),
        (
            FaultInjection::default().fail_parse_matching("no ", 1),
            "no user unused",
            None,
            false,
        ),
    ] {
        let fixture = fixture("router", faults).await?;
        let browser = fixture.login("admin").await?;
        let request = form(&[("line", line), ("confirm", "yes"), ("confirm_name", "home")]);

        let response = fixture
            .post("/ui/r/home/console/cli/send", &browser, &request)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await?;
        let label = format!("{line} {:?}: {body}", key.map(MessageKey::id));
        for other in ARMED_KEYS {
            assert_eq!(body.contains(&en(other)), key == Some(other), "{label}");
        }
        match key {
            Some(shown) => assert!(body.contains(&en(shown)), "{label}"),
            None => assert!(body.contains("injected"), "the router's refusal: {label}"),
        }
        if key == Some(keys::MANAGEMENT_DISARM_FAILED) {
            let config = fixture.handle().running_config_text();
            assert!(config.contains("port 8430"), "applied: {label}");
        }
        // A refused arm left no timer on the fake, though kcc cannot know that.
        let running = armed && key != Some(keys::MANAGEMENT_NOT_SENT_ARMED);
        assert_eq!(fixture.handle().recovery_armed(), running, "{label}");
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "web.console_cli")
            .ok_or("missing web audit")?;
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            armed.then_some(&json!(true)),
            "{failed:?}"
        );
        if armed {
            assert_eq!(failed.outcome, "failed", "{failed:?}");
        }
    }
    Ok(())
}
