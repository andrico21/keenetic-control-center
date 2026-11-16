//! What a migration keeps sealed, and for how long.
//!
//! The source and the typed passwords are deleted when the run finishes or expires, after
//! a day without change, and (the passwords) when the source or target changes; passwords
//! are mapped by user name.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;
    use std::{fs, path::PathBuf, time::UNIX_EPOCH};

    use axum::http::StatusCode;
    use tokio::time::{advance, pause, resume};

    use crate::{
        flow::{
            NEW_PASSWORD, moved, seed_source, stream, to_inputs, to_preview, to_review, value_of,
        },
        setup,
        support::{
            outcome::TestResult,
            page::text,
            web::{Browser, Fixture},
        },
    };

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

    /// Fails unless the run at `page` keeps neither its sealed source nor its passwords.
    fn assert_gone(fixture: &Fixture, page: &str, why: &str) -> TestResult {
        for name in ["source.sealed", "passwords.sealed"] {
            assert!(!kept(fixture, page, name)?, "{name} is kept {why}");
        }
        Ok(())
    }

    /// The Unix second the record of the run at `page` last changed.
    fn changed(fixture: &Fixture, page: &str) -> TestResult<u64> {
        let modified = fs::metadata(directory(fixture, page)?.join("wizard.json"))?.modified()?;
        Ok(modified.duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// A migration at its preview, with its source and `alice`'s password sealed.
    async fn sealed_run(fixture: &Fixture) -> TestResult<(Browser, String)> {
        seed_source(fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(fixture, &admin).await?;
        to_preview(fixture, &admin, &page).await?;
        for name in ["source.sealed", "passwords.sealed"] {
            assert!(
                kept(fixture, &page, name)?,
                "{name} is sealed at the preview"
            );
        }
        Ok((admin, page))
    }

    /// W5-03: committing a migration deletes its sealed source and passwords.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn finishing_a_migration_deletes_its_sealed_parts() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = sealed_run(&fixture).await?;
        moved(
            &fixture
                .post_form(&format!("{page}/apply"), &admin, &[("confirm", "yes")])
                .await?,
            &page,
        )?;
        assert!(
            stream(&fixture, &admin, &page)
                .await?
                .contains("event: done")
        );
        moved(
            &fixture
                .post_form(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post_form(&format!("{page}/commit"), &admin, &[])
                .await?,
            &page,
        )?;
        assert_gone(&fixture, &page, "after the commit")
    }

    /// W5-03: an applied migration nobody finishes loses its sealed parts when the
    /// router's recovery timer runs out.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_expired_migration_deletes_its_sealed_parts() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = sealed_run(&fixture).await?;
        moved(
            &fixture
                .post_form(&format!("{page}/apply"), &admin, &[("confirm", "yes")])
                .await?,
            &page,
        )?;
        assert!(
            stream(&fixture, &admin, &page)
                .await?
                .contains("event: done")
        );
        pause();
        advance(Duration::from_secs(15 * 60 + 2)).await;
        resume();
        assert_eq!(
            fixture.get(&page, &admin).await?.status(),
            StatusCode::OK,
            "the run is still there"
        );
        assert_gone(&fixture, &page, "after the recovery window")
    }

    /// W5-03: a migration left at step 5 for more than a day loses its sealed parts
    /// when the wizard is next opened; the run itself stays.
    #[tokio::test]
    async fn an_abandoned_migration_deletes_its_sealed_parts() -> TestResult {
        let fixture = setup::fixture().await?;
        let (_admin, page) = sealed_run(&fixture).await?;
        let day = changed(&fixture, &page)?.saturating_add(DAY);
        fixture.clock().set(day);
        let admin = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/migrate", &admin).await?.status(),
            StatusCode::OK
        );
        assert!(kept(&fixture, &page, "source.sealed")?, "kept for the day");

        fixture.clock().set(day.saturating_add(1));
        let later = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/migrate", &later).await?.status(),
            StatusCode::OK
        );
        assert_gone(&fixture, &page, "after a day without change")?;
        assert!(directory(&fixture, &page)?.join("wizard.json").exists());
        Ok(())
    }

    /// W5-04: choosing the target again deletes the sealed passwords typed for the
    /// earlier choice.
    #[tokio::test]
    async fn choosing_another_target_deletes_the_sealed_passwords() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = sealed_run(&fixture).await?;
        moved(
            &fixture
                .post_form(&format!("{page}/back"), &admin, &[("step", "target")])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post_form(&format!("{page}/target"), &admin, &[("router", "ultra")])
                .await?,
            &page,
        )?;
        assert!(
            !kept(&fixture, &page, "passwords.sealed")?,
            "kept after another target"
        );
        Ok(())
    }

    /// W5-04: choosing the source again deletes the sealed passwords typed for the
    /// earlier choice.
    #[tokio::test]
    async fn choosing_another_source_deletes_the_sealed_passwords() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = sealed_run(&fixture).await?;
        moved(
            &fixture
                .post_form(&format!("{page}/back"), &admin, &[("step", "source")])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post_multipart(
                    &format!("{page}/source"),
                    &admin,
                    (&[("kind", "router"), ("router", "giga")], None),
                )
                .await?,
            &page,
        )?;
        assert!(
            !kept(&fixture, &page, "passwords.sealed")?,
            "kept after another source"
        );
        Ok(())
    }

    /// W5-16: a password typed in a row whose hidden user name is not the user the row
    /// stands for at the server is refused and applied to nobody.
    #[tokio::test]
    async fn a_password_is_never_applied_to_another_user() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_inputs(&fixture, &admin, &page).await?;
        let inputs = text(fixture.get(&page, &admin).await?).await?;
        let user = value_of(&inputs, "name=\"user-0\"").ok_or("a user row")?;
        let reconnect = value_of(&inputs, "name=\"reconnect_url\"").unwrap_or_default();
        let refused = fixture
            .post_form(
                &format!("{page}/inputs"),
                &admin,
                &[
                    ("user-0", "somebody-else"),
                    ("password-0", NEW_PASSWORD),
                    ("reconnect_url", &reconnect),
                ],
            )
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            !kept(&fixture, &page, "passwords.sealed")?,
            "nothing sealed"
        );
        let accepted = fixture
            .post_form(
                &format!("{page}/inputs"),
                &admin,
                &[
                    ("user-0", &user),
                    ("password-0", NEW_PASSWORD),
                    ("reconnect_url", &reconnect),
                ],
            )
            .await?;
        moved(&accepted, &page)?;
        assert!(kept(&fixture, &page, "passwords.sealed")?);
        Ok(())
    }
}
