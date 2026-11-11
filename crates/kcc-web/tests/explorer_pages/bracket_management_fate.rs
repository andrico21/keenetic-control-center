//! The Web batch panel names the management item's fate independently of siblings.

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use crate::{
    form, html,
    support::{Fixture, TestResult, text},
};

/// An accepted ordinary sibling cannot turn a refused management item into applied.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn refused_management_item_reports_unknown_armed() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let faults = FaultInjection::default()
            .refuse_batch_pointer("/ip/http/port".to_owned())
            .fail_parse_matching("no system", 1);
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?
                .with_migration(scenario),
        )
        .await?;
        let browser = fixture.login("admin").await?;
        let items = json!([
            {"ip":{"http":{"port":{"port":8431_u16}}}},
            {"system":{"description":{"description":"ordinary"}}}
        ]);

        let response = fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[
                    ("method", "POST"),
                    ("path", ""),
                    ("body", &serde_json::to_string(&items)?),
                    ("confirm", "yes"),
                ]),
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await?;
        assert!(
            body.contains(&html(&tr(
                Locale::En,
                keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
                None
            ))),
            "{mode}: {body}"
        );
        assert!(body.contains("injected batch refusal."), "{mode}: {body}");
        assert!(fixture.handle().recovery_armed());
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "web.console_rci")
            .ok_or("Web audit")?;
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            Some(&json!(true))
        );
    }
    Ok(())
}
