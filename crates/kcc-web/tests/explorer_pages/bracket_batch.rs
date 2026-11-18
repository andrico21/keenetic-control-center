//! Raw batch refusal and recovery cleanup remain independently visible.

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FaultInjection, bracket::Recovery};
use serde_json::json;

use super::fixture;
use crate::support::{
    outcome::TestResult,
    page::{form, html, text},
};

/// Batch recovery reports application only for accepted changes and keeps refusals; an
/// accepted ordinary sibling never makes a refused management item applied.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn batch_completion_controls_recovery_message() -> TestResult {
    for (refused, partial, armed) in [
        (true, false, true),
        (false, false, true),
        (true, true, true),
        (true, false, false),
    ] {
        let mut faults = FaultInjection::default();
        if refused {
            faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
        }
        if armed {
            faults = faults.fail_parse_matching(Recovery::FailSafeTimer.disarm(), 1);
        }
        let fixture = fixture("router", faults).await?;
        let browser = fixture.login("admin").await?;
        let mut items = vec![json!({"ip":{"http":{"port":{"port":8430_u16}}}})];
        if partial {
            items.push(json!({"system":{"description":{"description":"lab"}}}));
        }
        let body = serde_json::to_string(&items)?;
        let request = form(&[
            ("method", "POST"),
            ("path", ""),
            ("body", &body),
            ("confirm", "yes"),
        ]);

        let response = fixture
            .post("/ui/r/home/console/rci/send", &browser, &request)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let page = text(response).await?;
        let label = format!("refused={refused} partial={partial} armed={armed}: {page}");
        let key = if refused {
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
        } else {
            keys::MANAGEMENT_DISARM_FAILED
        };
        let message = html(&tr(Locale::En, key, None));
        assert_eq!(page.contains(&message), armed, "{label}");
        assert_eq!(page.contains("injected batch refusal."), refused, "{label}");
        assert_eq!(fixture.handle().recovery_armed(), armed, "{label}");
        let entries = fixture.audit()?;
        let batch = entries
            .iter()
            .find(|entry| entry.action == "router.change_batch")
            .ok_or("batch audit")?;
        let outcome = match (partial, refused) {
            (true, _) => "partially_applied_unsaved",
            (false, true) => "failed",
            (false, false) => "applied_unsaved",
        };
        assert_eq!(batch.outcome, outcome, "{label}");
        let entry = entries
            .iter()
            .find(|entry| entry.action == "web.console_rci")
            .ok_or("Web audit")?;
        assert_eq!(
            entry.params_redacted.get("fail_safe_armed"),
            armed.then_some(&json!(true)),
            "{label}"
        );
        if armed {
            assert_eq!(entry.outcome, "failed", "{label}");
        }
    }
    Ok(())
}
