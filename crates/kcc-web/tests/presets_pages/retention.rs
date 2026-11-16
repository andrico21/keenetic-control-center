//! How many preset runs a user keeps open and how long kcc keeps a run.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::{fs, path::PathBuf, time::UNIX_EPOCH};

    use axum::http::StatusCode;
    use kcc_i18n::keys;

    use crate::{
        flow::{DNS_LINES, capture, seed, start},
        setup,
        support::{
            outcome::TestResult,
            page::{en, text},
            web::Fixture,
        },
    };

    /// The directory of the run at `page`.
    fn directory(fixture: &Fixture, page: &str) -> TestResult<PathBuf> {
        let id = page.rsplit('/').next().ok_or("no run id")?;
        Ok(fixture.state_dir().join("migrations").join(id))
    }

    /// The Unix second the record of the run at `page` last changed.
    fn changed(fixture: &Fixture, page: &str) -> TestResult<u64> {
        let modified = fs::metadata(directory(fixture, page)?.join("preset.json"))?.modified()?;
        Ok(modified.duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// W5-06: a user keeps at most 10 unfinished preset runs; the 11th is refused with
    /// the reason, until a day without change makes the others abandoned.
    #[tokio::test]
    async fn an_eleventh_open_preset_run_is_refused_until_the_others_are_abandoned() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let mut last = String::new();
        for _ in 0_u32..10 {
            last = start(&fixture, &admin, &id).await?;
        }
        let refused = fixture
            .post_form(&format!("/ui/presets/{id}/apply"), &admin, &[])
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            text(refused)
                .await?
                .contains(&en(keys::WEB_WIZARD_RUNS_LIMIT)),
            "says why"
        );

        fixture
            .clock()
            .set(changed(&fixture, &last)? + 24 * 60 * 60 + 1);
        let again = fixture.login("admin").await?;
        drop(start(&fixture, &again, &id).await?);
        Ok(())
    }

    /// W5-06: a preset run whose record has not changed for 30 days is deleted when the
    /// presets are next opened.
    #[tokio::test]
    async fn a_preset_run_untouched_for_thirty_days_is_deleted() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let old = start(&fixture, &admin, &id).await?;
        fixture
            .clock()
            .set(changed(&fixture, &old)? + 30 * 24 * 60 * 60 + 1);
        let again = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/copy", &again).await?.status(),
            StatusCode::OK
        );
        assert!(
            !directory(&fixture, &old)?.exists(),
            "deleted after 30 days"
        );
        Ok(())
    }
}
