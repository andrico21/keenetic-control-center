//! HTTP receipts for preset closing failures.

#[path = "presets_pages/flow.rs"]
#[expect(
    dead_code,
    reason = "closing tests use the shared apply flow, not successful finish helpers"
)]
mod flow;
#[expect(
    dead_code,
    reason = "closing tests build the fixture with its mode and faults only"
)]
#[path = "presets_pages/setup.rs"]
mod setup;
#[path = "support/mod.rs"]
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
    use axum::{http::StatusCode, response::Response};
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::FaultInjection;
    use serde_json::json;

    use super::{
        flow,
        support::{
            outcome::TestResult,
            page::text,
            web::{Browser, Fixture},
        },
    };
    use crate::setup;

    /// Closing faults keep the preset timer visible in the page and audit.
    // NOT cancel-safe: the fixture applies settings before requesting save.
    async fn closing(mode: &str, step: &str, lost: bool) -> TestResult {
        let faults = if lost {
            FaultInjection::default().disconnect_after_parse(step.to_owned())
        } else {
            FaultInjection::default().fail_parse_matching(step, 1)
        };
        let fixture = setup::with_mode(mode, faults).await?;
        flow::seed(&fixture, "prod-1", &flow::DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id =
            flow::capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Closing DNS")).await?;
        let page = flow::start(&fixture, &admin, &id).await?;
        flow::to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::WEB_PRESETS_APPLIED, None)));
        let results = fixture
            .post_form(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);

        let (endpoint, form) = if step == "fail-safe rollback" {
            (
                format!("{page}/rollback"),
                vec![("confirm", "yes"), ("confirm_name", "lab-1")],
            )
        } else {
            (format!("{page}/save"), Vec::new())
        };
        let response = fixture.post_form(&endpoint, &admin, &form).await?;

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
            fixture.router("lab-1")?.recovery_armed(),
            !(lost && (mode == "router" || step == "no system reboot"))
        );
        let entries = fixture.audit()?;
        let failed = entries
            .iter()
            .find(|entry| {
                entry.action
                    == if step == "fail-safe rollback" {
                        "web.preset_rollback"
                    } else {
                        "web.preset_save"
                    }
            })
            .ok_or("missing preset finish audit")?;
        assert_eq!(failed.outcome, "failed");
        assert_eq!(
            failed.params_redacted,
            json!({"error": "router", "fail_safe_armed": true})
        );
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

    /// A refused preset rollback reports that recovery remains armed.
    #[tokio::test]
    async fn refused_preset_rollback_reports_armed() -> TestResult {
        closing("router", "fail-safe rollback", false).await
    }

    /// Applies a preset onto an extender whose router answers `fail_after` requests, then
    /// rolls back; returns the fixture, the run page and the rollback's answer.
    // NOT cancel-safe: the fixture applies settings and reboots the target.
    async fn extender_rollback(
        fail_after: Option<u64>,
    ) -> TestResult<(Fixture, Browser, String, Response)> {
        let faults = fail_after.map_or_else(FaultInjection::default, |count| {
            FaultInjection::default().fail_after_requests(count)
        });
        let fixture = setup::with_mode("extender", faults).await?;
        flow::seed(&fixture, "prod-1", &flow::DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = flow::capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Silent DNS")).await?;
        let page = flow::start(&fixture, &admin, &id).await?;
        flow::to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::WEB_PRESETS_APPLIED, None)));
        let results = fixture
            .post_form(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);
        let response = fixture
            .post_form(
                &format!("{page}/rollback"),
                &admin,
                &[("confirm", "yes"), ("confirm_name", "lab-1")],
            )
            .await?;
        Ok((fixture, admin, page, response))
    }

    /// A reboot the extender accepts before going silent says the router is restarting
    /// and leaves nothing to finish: a second rollback sends nothing.
    // NOT cancel-safe: both fixtures apply settings and reboot the target.
    #[tokio::test(start_paused = true)]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    async fn silent_extender_preset_rollback_reports_restarting() -> TestResult {
        let (baseline, _admin, _page, _rolled) = extender_rollback(None).await?;
        let reboot = baseline
            .router("lab-1")?
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
        let silent = fixture.router("lab-1")?.request_count();
        drop(
            fixture
                .post_form(
                    &format!("{page}/rollback"),
                    &admin,
                    &[("confirm", "yes"), ("confirm_name", "lab-1")],
                )
                .await?,
        );
        assert_eq!(
            fixture.router("lab-1")?.request_count(),
            silent,
            "no second reboot is sent"
        );
        Ok(())
    }

    /// A finish delaying past the 30 s budget is answered with its outcome when held.
    ///
    /// The audit append lock is held past 30 s, the save answer comes back as 200,
    /// not 408 (or 422 if applier failed, but not 408 which means the request timed out).
    // NOT cancel-safe: helper function with paused clock.
    async fn finish_held_past_budget() -> TestResult {
        use core::time::Duration;

        use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
        use tokio::{task::JoinHandle, time::sleep};

        let fixture = setup::with_mode("router", FaultInjection::default()).await?;
        flow::seed(&fixture, "prod-1", &flow::DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = flow::capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Budget DNS")).await?;
        let page = flow::start(&fixture, &admin, &id).await?;
        flow::to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = flow::apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&tr(Locale::En, keys::WEB_PRESETS_APPLIED, None)));
        let _results = fixture
            .post_form(&format!("{page}/results"), &admin, &[])
            .await?;

        // Hold the audit append lock past the request budget (30 s).
        let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
        let _held: JoinHandle<()> = tokio::spawn(async move {
            sleep(Duration::from_secs(60)).await;
            drop(lock);
        });

        // Save should be answered with 200 (the held bracket outcome), not 408.
        let response = fixture
            .post_form(&format!("{page}/save"), &admin, &[])
            .await?;
        let status = response.status();
        assert_ne!(
            status,
            StatusCode::REQUEST_TIMEOUT,
            "finish with held bracket should not get 408 timeout"
        );
        Ok(())
    }

    /// Preset finish outlives its request budget when held.
    #[tokio::test(start_paused = true)]
    async fn preset_finish_outlives_budget_when_held() -> TestResult {
        finish_held_past_budget().await
    }
}
