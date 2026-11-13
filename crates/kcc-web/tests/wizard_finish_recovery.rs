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
    use axum::{http::StatusCode, response::Response};
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use super::{
        flow,
        support::{Browser, Fixture, TestResult, text},
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
        assert_eq!(
            failed.params_redacted,
            json!({"error": "router", "fail_safe_armed": true})
        );
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

    /// Applies onto an extender whose router answers `fail_after` requests, then rolls
    /// back; returns the fixture, the wizard page and the rollback's answer.
    // NOT cancel-safe: the fixture applies settings and reboots the target.
    async fn extender_rollback(
        fail_after: Option<u64>,
    ) -> TestResult<(Fixture, Browser, String, Response)> {
        let faults = fail_after.map_or_else(FaultInjection::default, |count| {
            FaultInjection::default().fail_after_requests(count)
        });
        let fixture = Fixture::with_mode("extender", faults).await?;
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
        let response = fixture
            .post(
                &format!("{page}/rollback"),
                &admin,
                &[("confirm", "yes"), ("confirm_name", "ultra")],
            )
            .await?;
        Ok((fixture, admin, page, response))
    }

    /// A reboot the extender accepts before going silent says the router is restarting
    /// and leaves nothing to finish: a second rollback sends nothing.
    // NOT cancel-safe: both fixtures apply settings and reboot the target.
    #[tokio::test(start_paused = true)]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    async fn silent_extender_wizard_rollback_reports_restarting() -> TestResult {
        let (baseline, _admin, _page, _rolled) = extender_rollback(None).await?;
        let reboot = baseline
            .handle("ultra")?
            .request_log()
            .iter()
            .position(|record| record.command() == Some("system reboot"))
            .and_then(|index| u64::try_from(index).ok())
            .ok_or("the baseline rollback sends no reboot")?;
        drop(baseline);

        let (fixture, admin, page, response) =
            extender_rollback(Some(reboot.saturating_add(1))).await?;
        drop(response);
        let shown = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            shown.contains(&tr(Locale::En, keys::MIGRATE_ROLLBACK_SAVED, None)),
            "{shown}"
        );
        assert!(!shown.contains(&format!("{page}/rollback\"")), "{shown}");
        let silent = fixture.handle("ultra")?.request_count();
        drop(
            fixture
                .post(
                    &format!("{page}/rollback"),
                    &admin,
                    &[("confirm", "yes"), ("confirm_name", "ultra")],
                )
                .await?,
        );
        assert_eq!(
            fixture.handle("ultra")?.request_count(),
            silent,
            "no second reboot is sent"
        );
        Ok(())
    }

    /// A finish delaying past the 30 s budget is answered with its outcome when held.
    ///
    /// The audit append lock is held past 30 s, the commit answer comes back as 200,
    /// not 408 (or 422 if applier failed, but not 408 which means the request timed out).
    // NOT cancel-safe: helper function with paused clock.
    async fn finish_held_past_budget() -> TestResult {
        use core::time::Duration;

        use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
        use tokio::{task::JoinHandle, time::sleep};

        let fixture = Fixture::with_mode("router", FaultInjection::default()).await?;
        flow::seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = flow::to_review(&fixture, &admin).await?;
        flow::to_preview(&fixture, &admin, &page).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::MIGRATE_APPLY_VERIFIED, None)));
        let _results = fixture
            .post(&format!("{page}/results"), &admin, &[])
            .await?;

        // Hold the audit append lock past the request budget (30 s).
        let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
        let _held: JoinHandle<()> = tokio::spawn(async move {
            sleep(Duration::from_secs(60)).await;
            drop(lock);
        });

        // Commit should be answered with 200 (the held bracket outcome), not 408.
        let response = fixture.post(&format!("{page}/commit"), &admin, &[]).await?;
        let status = response.status();
        assert_ne!(
            status,
            StatusCode::REQUEST_TIMEOUT,
            "finish with held bracket should not get 408 timeout"
        );
        Ok(())
    }

    /// Wizard finish outlives its request budget when held.
    #[tokio::test(start_paused = true)]
    async fn wizard_finish_outlives_budget_when_held() -> TestResult {
        finish_held_past_budget().await
    }
}
