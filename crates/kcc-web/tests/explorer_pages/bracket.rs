//! Management recovery does not strand a raw destructive role.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the recovery contract"
)]
use std::io::{self, Write as _};

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use crate::{
    en, form,
    support::{Fixture, TestResult, text},
};

#[path = "bracket_batch.rs"]
mod batch;
#[path = "bracket_management_fate.rs"]
mod management_fate;

/// A raw role without ordinary write permission closes its management bracket.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn management_bracket_without_write_permission() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario),
        )
        .await?;
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
        let log = fixture.handle().request_log();
        let commands = log
            .iter()
            .filter_map(|record| record.command())
            .collect::<Vec<_>>();
        let (arm, disarm) = if mode == "router" {
            (
                "system configuration fail-safe timer reboot 300",
                "no system configuration fail-safe timer",
            )
        } else {
            ("system reboot 300", "no system reboot")
        };
        assert!(
            commands.contains(&arm) && commands.contains(&disarm),
            "Web rawdes {mode}: {commands:?}"
        );
        writeln!(io::stderr(), "BRACKET Web rawdes {mode}: arm + disarm")?;
    }
    Ok(())
}

/// A protocol refusal of disarm reports an applied change with recovery still armed.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn management_bracket_disarm_failure_reports_applied() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("no system", 1)).await?;
    let browser = fixture.login("admin").await?;
    let request = form(&[("line", "ip http port 8082"), ("confirm", "yes")]);
    let response = fixture
        .post("/ui/r/home/console/cli/send", &browser, &request)
        .await?;
    assert!(
        fixture.handle().running_config_text().contains("port 8082"),
        "management port applied"
    );
    let body = text(response).await?;
    assert!(body.contains(&en(keys::MANAGEMENT_DISARM_FAILED)), "{body}");
    Ok(())
}

/// Every unfinished bracket retains its recovery message and audit flag in both modes.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn bracket_failure_matrix_retains_recovery() -> TestResult {
    for mode in ["router", "extender"] {
        for (faults, line, applied, armed) in [
            (
                FaultInjection::default().disconnect_after_parse("ip http port".to_owned()),
                "ip http port 8430",
                false,
                true,
            ),
            (
                FaultInjection::default().fail_parse_matching("no system", 1),
                "ip http port 8430",
                true,
                true,
            ),
            (
                FaultInjection::default().fail_parse_matching("no ", 2),
                "no user unused",
                false,
                true,
            ),
            (
                FaultInjection::default().fail_parse_matching("no ", 1),
                "no user unused",
                false,
                false,
            ),
        ] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let fixture = Fixture::with_router(
                FakeRouter::builder(Profile::default())
                    .faults(faults)
                    .build()?
                    .with_migration(scenario),
            )
            .await?;
            let browser = fixture.login("admin").await?;
            let response = fixture
                .post(
                    "/ui/r/home/console/cli/send",
                    &browser,
                    &form(&[("line", line), ("confirm", "yes"), ("confirm_name", "home")]),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = text(response).await?;
            let mut args = FluentArgs::new();
            args.set("minutes", "5");
            let unknown = if line == "no user unused" {
                tr(Locale::En, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED, None)
            } else {
                tr(Locale::En, keys::WEB_EXPLORER_ARMED, Some(&args))
            };
            assert_eq!(body.contains(&unknown), armed && !applied, "{mode}: {body}");
            if line == "no user unused" {
                assert!(
                    body.contains("injected"),
                    "router refusal remains visible: {body}"
                );
            }
            assert_eq!(
                body.contains(&en(keys::MANAGEMENT_DISARM_FAILED)),
                applied,
                "{mode}: {body}"
            );
            assert_eq!(fixture.handle().recovery_armed(), armed);
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
            writeln!(
                io::stderr(),
                "RECOVERY Web {mode} {line}: applied={applied} armed={armed} audit={armed} fake={armed}"
            )?;
        }
    }
    Ok(())
}
