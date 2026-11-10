//! The RCI console gates nested commands before transmission.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions establish the console security boundary"
)]

use axum::http::StatusCode;

use crate::{
    form,
    support::{Fixture, TestResult, text},
};

/// Every destructive request shape asks for the router name and refuses a raw writer who
/// deliberately lacks `Destructive`.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn nested_destructive_console_requests_need_typed_name_and_permission() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let raw_writer = fixture.login("raw-writer").await?;
    drop(fixture.get("/ui/r/home/console/rci", &admin).await?);
    let before = fixture.handle().request_count();
    for (path, body) in [
        ("", r#"{"system reboot":{}}"#),
        ("user", r#"{"name":"victim","no":true}"#),
        ("system reboot", "{}"),
        ("system", r#"{"reboot":{}}"#),
        ("", r#"{"system":{"configuration":{"factory-reset":{}}}}"#),
    ] {
        let request = form(&[
            ("method", "POST"),
            ("path", path),
            ("body", body),
            ("confirm", "yes"),
        ]);
        let asked = text(
            fixture
                .post("/ui/r/home/console/rci/send", &admin, &request)
                .await?,
        )
        .await?;
        assert!(
            asked.contains("name=\"confirm_name\""),
            "typed name required: {path}: {asked}"
        );
        let denied = fixture
            .post("/ui/r/home/console/rci/send", &raw_writer, &request)
            .await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "no router requests: {path}"
        );
    }
    Ok(())
}

/// A destructive sibling cannot disable the management recovery timer.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn mixed_console_requests_arm_and_disarm_recovery() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let request = form(&[
        ("method", "POST"),
        ("path", ""),
        (
            "body",
            r#"[{"ip":{"http":{"port":{"port":8082}}}},{"mws":{"member":{"reboot":{}}}}]"#,
        ),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ]);
    let response = fixture
        .post("/ui/r/home/console/rci/send", &admin, &request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let log = fixture.handle().request_log();
    let timers = log
        .iter()
        .filter_map(|record| record.command())
        .filter(|line| {
            let command = line.strip_prefix("no ").unwrap_or(line);
            command.starts_with("system configuration fail-safe timer")
                || command.starts_with("system reboot")
        })
        .collect::<Vec<_>>();
    assert_eq!(timers.len(), 2, "arm and disarm: {timers:?}");
    assert!(
        timers.iter().any(|line| line.starts_with("no ")),
        "disarm: {timers:?}"
    );
    Ok(())
}

/// DELETE and negative CLI lines share the raw destructive refusal boundary.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn delete_and_negative_cli_require_permission_without_requests() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get("/ui/r/home/console/rci", &admin).await?);
    let before = fixture.handle().request_count();
    for (endpoint, request) in [
        (
            "/ui/r/home/console/rci/send",
            form(&[
                ("method", "DELETE"),
                ("path", "user"),
                ("body", r#"{"name":"victim"}"#),
                ("confirm", "yes"),
            ]),
        ),
        (
            "/ui/r/home/console/cli/send",
            form(&[("line", "no user victim"), ("confirm", "yes")]),
        ),
    ] {
        let asked = text(fixture.post(endpoint, &admin, &request).await?).await?;
        assert!(
            asked.contains("name=\"confirm_name\""),
            "typed name: {asked}"
        );
        let denied = fixture.post(endpoint, &operator, &request).await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(fixture.handle().request_count(), before);
    }
    Ok(())
}

/// A confirmed destructive DELETE or negative CLI line on a management node runs inside
/// the recovery timer: armed before the request and disarmed after it.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn confirmed_management_delete_and_cli_arm_and_disarm_recovery() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    for (endpoint, request) in [
        (
            "/ui/r/home/console/rci/send",
            form(&[
                ("method", "DELETE"),
                ("path", "user"),
                ("body", r#"{"name":"victim"}"#),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ),
        (
            "/ui/r/home/console/cli/send",
            form(&[
                ("line", "no user victim"),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ),
    ] {
        let before = fixture.handle().request_log().len();
        let response = fixture.post(endpoint, &admin, &request).await?;
        assert_eq!(response.status(), StatusCode::OK, "{endpoint}");
        let log = fixture.handle().request_log();
        let timers = log
            .iter()
            .skip(before)
            .filter_map(|record| record.command())
            .filter(|line| {
                let command = line.strip_prefix("no ").unwrap_or(line);
                command.starts_with("system configuration fail-safe timer")
                    || command.starts_with("system reboot")
            })
            .collect::<Vec<_>>();
        assert_eq!(timers.len(), 2, "{endpoint}: arm and disarm: {timers:?}");
        assert!(
            timers.last().is_some_and(|line| line.starts_with("no ")),
            "{endpoint}: disarm last: {timers:?}"
        );
    }
    Ok(())
}
