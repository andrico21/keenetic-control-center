//! Namespace batches retain the confirmation dialog, unsaved badge and change audit.
use axum::http::StatusCode;
use kcc_i18n::keys;
use serde_json::json;

use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
    web::Fixture,
};

/// Empty namespace subtrees cannot ride a Show request through the Web read route.
// NOT cancel-safe: the fixture owns router tasks and writes until teardown.
#[tokio::test]
async fn namespace_batches_require_confirmation_and_report_unsaved() -> TestResult {
    for items in [
        json!([{"ip":{"http":{}}}]),
        json!([{"show":{"version":{}}},{"ip":{"http":{}}}]),
        json!([{"show":{"version":{}},"ip":{"http":{}}}]),
    ] {
        let fixture = Fixture::new().await?;
        let browser = fixture.login("admin").await?;
        let data = serde_json::to_string(&items)?;
        let before = fixture.handle().request_log().len();
        let asked = text(
            fixture
                .post(
                    "/ui/r/home/console/rci/send",
                    &browser,
                    &form(&[("method", "POST"), ("path", ""), ("body", &data)]),
                )
                .await?,
        )
        .await?;
        assert!(
            asked.contains(&en(keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE)),
            "{items}: {asked}"
        );
        let completed_log = fixture.handle().request_log();
        assert_eq!(
            completed_log
                .iter()
                .skip(before)
                .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                .count(),
            0
        );
        assert!(
            fixture
                .audit()?
                .iter()
                .all(|entry| entry.action != "router.change_batch"),
            "dialog sends no change"
        );

        let response = fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[
                    ("method", "POST"),
                    ("path", ""),
                    ("body", &data),
                    ("confirm", "yes"),
                ]),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await?;
        assert!(
            body.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
            "{items}: {body}"
        );
        assert!(body.contains("id=\"unsaved-badge\""), "{body}");
        let entries = fixture.audit()?;
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.action == "router.change_batch")
                .map(|entry| entry.outcome.as_str())
                .collect::<Vec<_>>(),
            ["applied_unsaved"]
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.action == "web.console_rci")
                .map(|entry| entry.outcome.as_str())
                .collect::<Vec<_>>(),
            ["success"]
        );
        let log = fixture.handle().request_log();
        assert_eq!(
            log.iter()
                .skip(before)
                .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                .count(),
            1
        );
    }
    Ok(())
}
