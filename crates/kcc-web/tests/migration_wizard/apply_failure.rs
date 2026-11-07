//! What the apply does when it cannot go on: a setting the router refuses stops it and
//! the rollback (the router name typed) restores the router; a setting kcc cannot send
//! yet stops it before any change.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::keys;
    use kcc_testkit::FaultInjection;

    use crate::{
        en,
        flow::{apply, moved, seed_source, to_preview, to_review},
        support::{Fixture, TestResult, header_text, text},
    };

    #[tokio::test]
    async fn a_refused_setting_stops_the_apply_and_the_rollback_restores_the_router() -> TestResult
    {
        let faults = FaultInjection::default().fail_parse_matching("migrated-office", 1);
        let fixture = Fixture::with_target_faults(faults).await?;
        seed_source(&fixture).await?;
        let before = fixture.handle("ultra")?.startup_config_text();
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let stopped = apply(&fixture, &admin, &page).await?;
        assert!(
            stopped.contains("data-outcome=\"rejected\"")
                && stopped.contains(&en(keys::WEB_MIGRATE_FAILURE_STOPPED)),
            "the refused line and why the apply stopped: {stopped}"
        );
        let stop = fixture.post(&format!("{page}/stop"), &admin, &[]).await?;
        assert!(
            text(stop)
                .await?
                .contains(&en(keys::WEB_EXPLORER_JOB_NOT_RUNNING)),
            "Stop after the end says the apply no longer runs"
        );
        moved(
            &fixture
                .post(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let results = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            results.contains(&format!("hx-post=\"{page}/rollback\""))
                && !results.contains(&format!("hx-post=\"{page}/commit\"")),
            "roll back, never commit a stopped apply: {results}"
        );
        let rollback = format!("{page}/rollback");
        let asked = fixture.post(&rollback, &admin, &[]).await?;
        assert!(
            text(asked).await?.contains("name=\"confirm_name\""),
            "the router name is asked"
        );
        let wrong = fixture
            .post(
                &rollback,
                &admin,
                &[("confirm", "yes"), ("confirm_name", "giga")],
            )
            .await?;
        assert!(
            text(wrong).await?.contains("aria-invalid=\"true\""),
            "a wrong name is refused"
        );
        let rolled = fixture
            .post(
                &rollback,
                &admin,
                &[("confirm", "yes"), ("confirm_name", "ultra")],
            )
            .await?;
        moved(&rolled, &page)?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_MIGRATE_FINISH_ROLLED_BACK)),
            "step 9: {report}"
        );
        let target = fixture.handle("ultra")?;
        assert_eq!(
            target.startup_config_text(),
            before,
            "the saved configuration"
        );
        assert!(
            !target.running_config_text().contains("migrated-office"),
            "nothing of the migration runs"
        );
        Ok(())
    }

    /// Pins the gap plan row 61 closes.
    ///
    /// The planner copies a setting inside an interface section that the catalog cannot
    /// check yet, so the engine refuses the plan before any change. Once the catalog
    /// checks such lines, this setting applies and the test needs another setting kcc
    /// cannot send, or goes.
    #[tokio::test]
    async fn a_setting_kcc_cannot_send_yet_stops_the_apply_before_any_change() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let source = fixture.registry().client("giga").await?;
        for line in [
            "interface Bridge19 security-level protected",
            "system configuration save",
        ] {
            drop(source.parse(line).await?);
        }
        let target = fixture.handle("ultra")?;
        let (running, saved) = (target.running_config_text(), target.startup_config_text());
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let refused = apply(&fixture, &admin, &page).await?;
        assert!(
            refused.contains(&en(keys::WEB_MIGRATE_FAILURE_VALIDATION))
                && !refused.contains("event: line"),
            "nothing was sent, and the step says why: {refused}"
        );
        assert_eq!(target.running_config_text(), running, "running unchanged");
        assert_eq!(target.startup_config_text(), saved, "startup unchanged");
        moved(
            &fixture
                .post(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let results = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            results.contains(&format!("hx-post=\"{page}/retry\""))
                && !results.contains(&format!("hx-post=\"{page}/rollback\"")),
            "back to the preview; nothing to roll back: {results}"
        );
        let retried = fixture.post(&format!("{page}/retry"), &admin, &[]).await?;
        moved(&retried, &page)?;
        let preview = fixture.get(&page, &admin).await?;
        assert_eq!(preview.status(), StatusCode::OK, "the preview");
        assert!(
            text(preview)
                .await?
                .contains(&en(keys::WEB_MIGRATE_PREVIEW_TITLE)),
            "the preview again"
        );
        assert!(
            header_text(&retried, "hx-redirect").is_some(),
            "the browser opens it"
        );
        Ok(())
    }
}
