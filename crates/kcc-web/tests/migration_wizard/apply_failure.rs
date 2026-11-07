//! What the apply does when it cannot go on: a setting the router refuses stops it and
//! the rollback (the router name typed) restores the router; a setting kcc cannot send
//! is left out before apply.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::keys;
    use kcc_testkit::FaultInjection;

    use crate::{
        en,
        flow::{apply, form_values, moved, seed_source, to_preview, to_review},
        start,
        support::{Fixture, TestResult, text},
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

    /// An unsupported setting is visible at review but absent from preview and apply.
    #[tokio::test]
    async fn a_setting_kcc_cannot_send_is_listed_as_unsupported_and_never_reaches_the_router()
    -> TestResult {
        let unsupported = "future command value";
        let faults = FaultInjection::default().fail_parse_matching(unsupported, 1);
        let fixture = Fixture::with_target_faults(faults).await?;
        let admin = fixture.login("admin").await?;
        let page = start(&fixture, &admin).await?;
        let source = format!(
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge19\n description migrated-office\n!\n{unsupported}\n"
        );
        moved(
            &fixture
                .post_source(
                    &format!("{page}/source"),
                    &admin,
                    &[("kind", "file")],
                    Some(&source),
                )
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post(&format!("{page}/target"), &admin, &[("router", "ultra")])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post(&format!("{page}/target/continue"), &admin, &[])
                .await?,
            &page,
        )?;
        let maps = text(fixture.get(&page, &admin).await?).await?;
        let fields = form_values(&maps);
        let pairs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        moved(
            &fixture
                .post(&format!("{page}/mapping"), &admin, &pairs)
                .await?,
            &page,
        )?;
        let review = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            review.contains(unsupported)
                && review.contains("data-fate=\"unsupported\"")
                && review.contains(&en(keys::WEB_MIGRATE_FATE_UNSUPPORTED)),
            "review identifies the unsupported setting: {review}"
        );
        to_preview(&fixture, &admin, &page).await?;
        let preview = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            !preview.contains(unsupported)
                && preview.contains("interface Bridge19 description migrated-office"),
            "preview excludes the unsupported setting but keeps the normal one: {preview}"
        );
        let applied = apply(&fixture, &admin, &page).await?;
        assert!(
            applied.contains(&en(keys::MIGRATE_APPLY_VERIFIED)),
            "the supported plan completes: {applied}"
        );
        moved(
            &fixture
                .post(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let results = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            results.contains(&format!("hx-post=\"{page}/commit\"")),
            "the verified apply can commit: {results}"
        );
        moved(
            &fixture.post(&format!("{page}/commit"), &admin, &[]).await?,
            &page,
        )?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_MIGRATE_FINISH_COMMITTED)),
            "the migration finishes committed: {report}"
        );
        let target = fixture.handle("ultra")?;
        let running = target.running_config_text();
        assert!(
            !running.contains(unsupported) && running.contains("description migrated-office"),
            "the unsupported setting never reaches the target and the normal setting does: {running}"
        );
        assert!(
            target.request_log().iter().all(|request| {
                !request.path().contains(unsupported)
                    && request.query().iter().all(|(name, value)| {
                        !name.contains(unsupported) && !value.contains(unsupported)
                    })
            }),
            "the sanitized target request log contains no unsupported setting"
        );
        Ok(())
    }
}
