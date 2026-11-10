//! Management recovery does not strand a raw destructive role.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the recovery contract"
)]
use std::io::{self, Write as _};

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};

use crate::{
    en, form,
    support::{Fixture, TestResult, text},
};

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
