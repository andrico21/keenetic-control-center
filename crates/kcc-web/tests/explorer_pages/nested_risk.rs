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

/// Every destructive request shape asks for the router name and refuses an operator.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn nested_destructive_console_requests_need_typed_name_and_permission() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get("/ui/r/home/console/rci", &admin).await?);
    let before = fixture.handle().request_count();
    for (path, body) in [
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
            .post("/ui/r/home/console/rci/send", &operator, &request)
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
