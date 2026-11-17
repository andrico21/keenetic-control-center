//! HTTP receipts for the wizards' closing failures.
//!
//! Every scenario runs for both wizards that finish an apply: a migration onto `ultra`,
//! kept by `commit`, and a preset run onto `lab-1`, kept by `save` ([`Wizard`]).

#[path = "migration_wizard/flow.rs"]
mod migration_flow;
#[expect(
    dead_code,
    reason = "closing tests build the fixture with its mode and faults only"
)]
#[path = "migration_wizard/setup.rs"]
mod migration_setup;
#[path = "presets_pages/flow.rs"]
#[expect(
    dead_code,
    reason = "closing tests use the shared apply flow, not successful finish helpers"
)]
mod preset_flow;
#[expect(
    dead_code,
    reason = "closing tests build the fixture with its mode and faults only"
)]
#[path = "presets_pages/setup.rs"]
mod preset_setup;
#[path = "support/mod.rs"]
#[expect(
    dead_code,
    reason = "closing tests use only the HTTP and audit parts of the shared fixture"
)]
mod support;
#[path = "finish_recovery/wizard.rs"]
mod wizard;

use axum::response::Response;

use crate::support::{
    outcome::TestResult,
    page::header_text,
    web::{Browser, Fixture},
};

/// Starts a migration through its public HTTP route.
///
/// # Errors
/// Returns request failures or a missing navigation target.
// NOT cancel-safe: creates a wizard record.
async fn start(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
    redirected(
        &fixture
            .post_form("/ui/migrate", browser, &[("mode", "migrate")])
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
        support::{
            outcome::TestResult,
            page::{header_text, text},
            web::{Browser, Fixture},
        },
        wizard::Wizard,
    };

    /// Closing faults keep the wizard timer visible in the page and audit.
    // NOT cancel-safe: the fixture applies settings before the finish.
    async fn closing(wizard: Wizard, (mode, step, lost): (&str, &str, bool)) -> TestResult {
        let faults = if lost {
            FaultInjection::default().disconnect_after_parse(step.to_owned())
        } else {
            FaultInjection::default().fail_parse_matching(step, 1)
        };
        let (fixture, admin, page) = wizard.at_results(mode, faults).await?;
        let rollback = step == "fail-safe rollback";
        let (endpoint, form) = if rollback {
            (format!("{page}/rollback"), wizard.rollback_form().to_vec())
        } else {
            (format!("{page}/{}", wizard.keep()), Vec::new())
        };
        let response = fixture.post_form(&endpoint, &admin, &form).await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = text(response).await?;
        let shown = if step == "no system reboot" {
            keys::FINISH_SAVED_ARMED
        } else {
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
        };
        assert!(body.contains(&tr(Locale::En, shown, None)), "{body}");
        assert_eq!(
            fixture.router(wizard.target())?.recovery_armed(),
            !(lost && (mode == "router" || step == "no system reboot"))
        );
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == wizard.audited(rollback))
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
    async fn native_commit_reports_armed() -> TestResult {
        for wizard in Wizard::ALL {
            for lost in [false, true] {
                closing(wizard, ("router", "fail-safe commit", lost)).await?;
            }
        }
        Ok(())
    }

    /// Scheduled save and disarm failures report the timer and known persistence separately.
    #[tokio::test]
    async fn scheduled_finish_reports_armed() -> TestResult {
        for wizard in Wizard::ALL {
            for step in ["system configuration save", "no system reboot"] {
                for lost in [false, true] {
                    closing(wizard, ("extender", step, lost)).await?;
                }
            }
        }
        Ok(())
    }

    /// A refused rollback reports that recovery remains armed.
    #[tokio::test]
    async fn refused_rollback_reports_armed() -> TestResult {
        for wizard in Wizard::ALL {
            closing(wizard, ("router", "fail-safe rollback", false)).await?;
        }
        Ok(())
    }

    /// Applies onto an extender whose router answers `fail_after` requests, then rolls
    /// back; returns the fixture, the admin, the run's page and the rollback's answer.
    // NOT cancel-safe: the fixture applies settings and reboots the target.
    async fn extender_rollback(
        wizard: Wizard,
        fail_after: Option<u64>,
    ) -> TestResult<(Fixture, Browser, String, Response)> {
        let faults = fail_after.map_or_else(FaultInjection::default, |count| {
            FaultInjection::default().fail_after_requests(count)
        });
        let (fixture, admin, page) = wizard.at_results("extender", faults).await?;
        let response = fixture
            .post_form(&format!("{page}/rollback"), &admin, &wizard.rollback_form())
            .await?;
        Ok((fixture, admin, page, response))
    }

    /// A reboot the extender accepts before going silent says the router is restarting
    /// and leaves nothing to finish: a second rollback sends nothing.
    // NOT cancel-safe: both fixtures apply settings and reboot the target.
    #[tokio::test(start_paused = true)]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    async fn silent_extender_rollback_reports_restarting() -> TestResult {
        for wizard in Wizard::ALL {
            let (baseline, _admin, _page, _rolled) = extender_rollback(wizard, None).await?;
            let reboot = baseline
                .router(wizard.target())?
                .request_log()
                .iter()
                .position(|record| record.command() == Some("system reboot"))
                .and_then(|index| u64::try_from(index).ok())
                .ok_or("the baseline rollback sends no reboot")?;
            drop(baseline);

            let (fixture, admin, page, response) =
                extender_rollback(wizard, Some(reboot.saturating_add(1))).await?;
            drop(response);
            let shown = text(fixture.get(&page, &admin).await?).await?;
            assert!(
                shown.contains(&tr(Locale::En, keys::MIGRATE_ROLLBACK_SAVED, None)),
                "{shown}"
            );
            assert!(!shown.contains(&format!("{page}/rollback\"")), "{shown}");
            let silent = fixture.router(wizard.target())?.request_count();
            drop(
                fixture
                    .post_form(&format!("{page}/rollback"), &admin, &wizard.rollback_form())
                    .await?,
            );
            assert_eq!(
                fixture.router(wizard.target())?.request_count(),
                silent,
                "no second reboot is sent"
            );
        }
        Ok(())
    }

    /// W2-14: a finish held past the 30 s request budget is answered with its own end.
    ///
    /// The audit append lock is held for 60 s: the run moves on (200 with its redirect,
    /// never 408, 409, 422 or 500), and its keep is audited `done` once the lock is free.
    // NOT cancel-safe: the fixture applies settings; the clock is paused.
    #[tokio::test(start_paused = true)]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    async fn finish_outlives_its_budget_when_held() -> TestResult {
        use core::time::Duration;

        use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
        use tokio::{task::JoinHandle, time::sleep};

        for wizard in Wizard::ALL {
            let (fixture, admin, page) = wizard
                .at_results("router", FaultInjection::default())
                .await?;
            let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
            let held: JoinHandle<()> = tokio::spawn(async move {
                sleep(Duration::from_secs(60)).await;
                drop(lock);
            });

            let response = fixture
                .post_form(&format!("{page}/{}", wizard.keep()), &admin, &[])
                .await?;

            assert_eq!(response.status(), StatusCode::OK, "{wizard:?}");
            assert_eq!(
                header_text(&response, "hx-redirect").as_deref(),
                Some(page.as_str()),
                "{wizard:?}: the run moves on"
            );
            held.await?;
            assert_eq!(fixture.audit_flushed().await, 0, "{wizard:?}: written");
            assert_eq!(
                fixture.outcomes(wizard.audited(false))?,
                ["done"],
                "{wizard:?}"
            );
        }
        Ok(())
    }
}
