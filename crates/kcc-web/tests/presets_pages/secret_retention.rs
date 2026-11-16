//! What a preset run keeps sealed, and for how long.
//!
//! A copy's settings and the typed passwords are deleted when the run finishes, after a
//! day without change, and (the passwords) when the target changes.

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

    use crate::{
        flow::{apply, capture, finish, moved, redirected, seed, start, to_preview},
        setup,
        support::{
            outcome::TestResult,
            web::{Browser, Fixture},
        },
    };

    /// The password typed for `alice` on the target.
    const TARGET_PASSWORD: &str = "alice-target-passphrase";

    /// Seeds `prod-1` with a user, so the settings need a typed password.
    async fn seeded(fixture: &Fixture) -> TestResult {
        let user = format!("user alice password plain {TARGET_PASSWORD}-source");
        seed(fixture, "prod-1", &[&user]).await
    }

    /// A day, in seconds.
    const DAY: u64 = 24 * 60 * 60;

    /// The directory of the run at `page`.
    fn directory(fixture: &Fixture, page: &str) -> TestResult<PathBuf> {
        let id = page.rsplit('/').next().ok_or("no run id")?;
        Ok(fixture.state_dir().join("migrations").join(id))
    }

    /// Whether the run at `page` still keeps the sealed part `name`.
    fn kept(fixture: &Fixture, page: &str, name: &str) -> TestResult<bool> {
        Ok(directory(fixture, page)?.join(name).exists())
    }

    /// The Unix second the record of the run at `page` last changed.
    fn changed(fixture: &Fixture, page: &str) -> TestResult<u64> {
        let modified = fs::metadata(directory(fixture, page)?.join("preset.json"))?.modified()?;
        Ok(modified.duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// A run of a saved preset at its preview, with `alice`'s password sealed.
    async fn preset_run(fixture: &Fixture, admin: &Browser) -> TestResult<String> {
        seeded(fixture).await?;
        let id = capture(fixture, admin, "prod-1", (&["router-users"], "Users")).await?;
        let page = start(fixture, admin, &id).await?;
        to_preview(
            fixture,
            admin,
            &page,
            ("lab-1", "merge", &[("password-0", TARGET_PASSWORD)]),
        )
        .await?;
        assert!(kept(fixture, &page, "passwords.sealed")?, "sealed");
        Ok(page)
    }

    /// A copy run at its preview, with its settings and `alice`'s password sealed.
    async fn copy_run(fixture: &Fixture, admin: &Browser) -> TestResult<String> {
        seeded(fixture).await?;
        let page = redirected(&fixture.post_form("/ui/copy", admin, &[]).await?)?;
        moved(
            &fixture
                .post_form(
                    &format!("{page}/source"),
                    admin,
                    &[("router", "prod-1"), ("group", "router-users")],
                )
                .await?,
            &page,
        )?;
        to_preview(
            fixture,
            admin,
            &page,
            ("lab-1", "merge", &[("password-0", TARGET_PASSWORD)]),
        )
        .await?;
        for name in ["preset.sealed", "passwords.sealed"] {
            assert!(kept(fixture, &page, name)?, "{name} sealed");
        }
        Ok(page)
    }

    /// Sets the clock past a day after the run at `page` last changed and opens the
    /// copy page, as a user does.
    async fn a_day_later(fixture: &Fixture, page: &str) -> TestResult {
        fixture
            .clock()
            .set(changed(fixture, page)?.saturating_add(DAY + 1));
        let admin = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/copy", &admin).await?.status(),
            StatusCode::OK
        );
        Ok(())
    }

    /// W5-03: finishing a run of a saved preset deletes its sealed passwords.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn finishing_a_preset_run_deletes_its_sealed_parts() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = preset_run(&fixture, &admin).await?;
        assert!(
            apply(&fixture, &admin, &page)
                .await?
                .contains("event: done")
        );
        finish(&fixture, &admin, &page, ("keep", &[])).await?;
        assert!(!kept(&fixture, &page, "passwords.sealed")?);
        Ok(())
    }

    /// N16: a run of a saved preset left before its last step loses its sealed
    /// passwords after a day without change.
    #[tokio::test]
    async fn an_abandoned_preset_run_deletes_its_sealed_passwords() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = preset_run(&fixture, &admin).await?;
        fixture
            .clock()
            .set(changed(&fixture, &page)?.saturating_add(DAY));
        let same = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/copy", &same).await?.status(),
            StatusCode::OK
        );
        assert!(
            kept(&fixture, &page, "passwords.sealed")?,
            "kept for the day"
        );

        a_day_later(&fixture, &page).await?;
        assert!(!kept(&fixture, &page, "passwords.sealed")?, "after the day");
        assert!(directory(&fixture, &page)?.join("preset.json").exists());
        Ok(())
    }

    /// W5-03, N16: a copy run left for a day loses its settings and passwords, and
    /// its settings are not used even before a sweep has run.
    #[tokio::test]
    async fn an_abandoned_copy_run_deletes_its_sealed_parts() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = copy_run(&fixture, &admin).await?;
        a_day_later(&fixture, &page).await?;
        for name in ["preset.sealed", "passwords.sealed"] {
            assert!(!kept(&fixture, &page, name)?, "{name} after the day");
        }
        Ok(())
    }

    /// W5-03: a copy run past its day is refused its settings before any sweep.
    #[tokio::test]
    async fn an_old_copy_run_is_refused_its_settings() -> TestResult {
        let fixture = setup::fixture().await?;
        seeded(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = redirected(&fixture.post_form("/ui/copy", &admin, &[]).await?)?;
        moved(
            &fixture
                .post_form(
                    &format!("{page}/source"),
                    &admin,
                    &[("router", "prod-1"), ("group", "router-users")],
                )
                .await?,
            &page,
        )?;
        fixture
            .clock()
            .set(changed(&fixture, &page)?.saturating_add(DAY + 1));
        let later = fixture.login("admin").await?;
        let refused = fixture
            .post_form(&format!("{page}/target"), &later, &[("router", "lab-1")])
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        Ok(())
    }

    /// W5-04: choosing the target again deletes the sealed passwords typed for the
    /// earlier choice.
    #[tokio::test]
    async fn choosing_another_target_deletes_the_sealed_passwords() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = preset_run(&fixture, &admin).await?;
        moved(
            &fixture
                .post_form(&format!("{page}/back"), &admin, &[("step", "target")])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post_form(&format!("{page}/target"), &admin, &[("router", "lab-1")])
                .await?,
            &page,
        )?;
        assert!(!kept(&fixture, &page, "passwords.sealed")?);
        Ok(())
    }
}
