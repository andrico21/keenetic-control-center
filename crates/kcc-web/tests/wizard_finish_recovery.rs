//! HTTP receipts for migration closing failures.
extern crate alloc;

#[path = "migration_wizard/flow.rs"]
mod flow;
#[path = "migration_wizard/setup.rs"]
mod setup;
#[path = "migration_wizard/support.rs"]
#[expect(
    dead_code,
    reason = "closing tests use only the HTTP and audit parts of the shared fixture"
)]
mod support;

use axum::response::Response;
use support::{Browser, Fixture, TestResult, header_text};

/// Starts the wizard through its public HTTP route.
///
/// # Errors
/// Returns request failures or a missing navigation target.
// NOT cancel-safe: creates a wizard record.
async fn start(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
    redirected(
        &fixture
            .post("/ui/migrate", browser, &[("mode", "migrate")])
            .await?,
    )
}

/// Reads the navigation target returned by a successful wizard step.
///
/// # Errors
/// Returns an error when the response has no navigation target.
fn redirected(response: &Response) -> TestResult<String> {
    header_text(response, "hx-redirect").ok_or_else(|| "missing wizard redirect".into())
}

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

    /// Closing faults keep the wizard timer visible in the page and audit.
    // NOT cancel-safe: the fixture applies settings before requesting commit.
    async fn closing(mode: &str, step: &str, lost: bool) -> TestResult {
        let faults = if lost {
            FaultInjection::default().disconnect_after_parse(step.to_owned())
        } else {
            FaultInjection::default().fail_parse_matching(step, 1)
        };
        let fixture = Fixture::with_mode(mode, faults).await?;
        flow::seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = flow::to_review(&fixture, &admin).await?;
        flow::to_preview(&fixture, &admin, &page).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::MIGRATE_APPLY_VERIFIED, None)));
        let results = fixture
            .post(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);

        let (endpoint, form) = if step == "fail-safe rollback" {
            (
                format!("{page}/rollback"),
                vec![("confirm", "yes"), ("confirm_name", "ultra")],
            )
        } else {
            (format!("{page}/commit"), Vec::new())
        };
        let response = fixture.post(&endpoint, &admin, &form).await?;

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
            fixture.handle("ultra")?.recovery_armed(),
            !(lost && (mode == "router" || step == "no system reboot"))
        );
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| {
                entry.action
                    == if step == "fail-safe rollback" {
                        "web.migrate_rollback"
                    } else {
                        "web.migrate_commit"
                    }
            })
            .ok_or("missing wizard finish audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.params_redacted, json!({"fail_safe_armed":true}));
        Ok(())
    }

    /// Native commit refusal and lost reply preserve the conservative recovery receipt.
    #[tokio::test]
    async fn native_wizard_commit_reports_armed() -> TestResult {
        for lost in [false, true] {
            closing("router", "fail-safe commit", lost).await?;
        }
        Ok(())
    }

    /// Scheduled save and disarm failures report the timer and known persistence separately.
    #[tokio::test]
    async fn scheduled_wizard_finish_reports_armed() -> TestResult {
        for step in ["system configuration save", "no system reboot"] {
            for lost in [false, true] {
                closing("extender", step, lost).await?;
            }
        }
        Ok(())
    }

    /// A refused wizard rollback reports that recovery remains armed.
    #[tokio::test]
    async fn refused_wizard_rollback_reports_armed() -> TestResult {
        closing("router", "fail-safe rollback", false).await
    }
}
