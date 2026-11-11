//! HTTP receipts for preset closing failures.
extern crate alloc;

#[path = "presets_pages/flow.rs"]
#[expect(
    dead_code,
    reason = "closing tests use the shared apply flow, not successful finish helpers"
)]
mod flow;
#[path = "presets_pages/setup.rs"]
mod setup;
#[path = "presets_pages/support.rs"]
#[expect(
    dead_code,
    reason = "closing tests use only the HTTP and audit parts of the shared fixture"
)]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "HTTP acceptance assertions establish recovery receipts"
)]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use super::{
        flow,
        support::{Fixture, TestResult, text},
    };

    /// Closing faults keep the preset timer visible in the page and audit.
    // NOT cancel-safe: the fixture applies settings before requesting save.
    async fn closing(mode: &str, step: &str, lost: bool) -> TestResult {
        let faults = if lost {
            FaultInjection::default().disconnect_after_parse(step.to_owned())
        } else {
            FaultInjection::default().fail_parse_matching(step, 1)
        };
        let fixture = Fixture::with_mode(mode, faults).await?;
        flow::seed(&fixture, "prod-1", &flow::DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id =
            flow::capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Closing DNS")).await?;
        let page = flow::start(&fixture, &admin, &id).await?;
        flow::to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::WEB_PRESETS_APPLIED, None)));
        let results = fixture
            .post(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);

        let response = fixture.post(&format!("{page}/save"), &admin, &[]).await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = text(response).await?;
        assert!(
            body.contains(&tr(
                Locale::En,
                if step == "no system reboot" {
                    keys::FINISH_SAVED_ARMED
                } else {
                    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
                },
                None
            )),
            "{body}"
        );
        assert_eq!(
            fixture.handle("lab-1")?.recovery_armed(),
            !(lost && (mode == "router" || step == "no system reboot"))
        );
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "web.preset_save")
            .ok_or("missing preset finish audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.params_redacted, json!({"fail_safe_armed":true}));
        Ok(())
    }

    /// Native commit refusal and lost reply preserve the conservative recovery receipt.
    #[tokio::test]
    async fn native_preset_commit_reports_armed() -> TestResult {
        for lost in [false, true] {
            closing("router", "fail-safe commit", lost).await?;
        }
        Ok(())
    }

    /// Scheduled save and disarm failures report the timer and known persistence separately.
    #[tokio::test]
    async fn scheduled_preset_finish_reports_armed() -> TestResult {
        for step in ["system configuration save", "no system reboot"] {
            for lost in [false, true] {
                closing("extender", step, lost).await?;
            }
        }
        Ok(())
    }
}
