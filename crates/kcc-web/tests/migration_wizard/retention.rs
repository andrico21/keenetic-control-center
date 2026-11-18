//! How many runs a user keeps open, how long kcc keeps a run, and what the list reads.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        path::PathBuf,
        process::Command,
        time::UNIX_EPOCH,
    };

    use axum::http::StatusCode;
    use kcc_i18n::keys;
    use tokio::time::timeout;

    use crate::{
        setup, start,
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
        let modified = fs::metadata(directory(fixture, page)?.join("wizard.json"))?.modified()?;
        Ok(modified.duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// W5-06: a user keeps at most 10 unfinished migrations; the 11th start is refused
    /// with the reason, until a day without change makes the others abandoned.
    #[tokio::test]
    async fn an_eleventh_open_migration_is_refused_until_the_others_are_abandoned() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let mut last = String::new();
        for _ in 0_u32..10 {
            last = start(&fixture, &admin).await?;
        }
        let refused = fixture
            .post_form("/ui/migrate", &admin, &[("mode", "migrate")])
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            text(refused)
                .await?
                .contains(&en(keys::WEB_WIZARD_RUNS_LIMIT)),
            "says why"
        );
        assert_eq!(
            fs::read_dir(fixture.state_dir().join("migrations"))?
                .filter(|entry| entry.as_ref().is_ok_and(|found| found.path().is_dir()))
                .count(),
            10,
            "no eleventh run"
        );

        fixture
            .clock()
            .set(changed(&fixture, &last)? + 24 * 60 * 60 + 1);
        let again = fixture.login("admin").await?;
        drop(start(&fixture, &again).await?);
        Ok(())
    }

    /// W5-06: a migration whose record has not changed for 30 days is deleted when the
    /// wizard is next opened.
    #[tokio::test]
    async fn a_migration_untouched_for_thirty_days_is_deleted() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let old = start(&fixture, &admin).await?;
        let kept = changed(&fixture, &old)? + 30 * 24 * 60 * 60;
        fixture.clock().set(kept);
        let again = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/migrate", &again).await?.status(),
            StatusCode::OK
        );
        assert!(directory(&fixture, &old)?.exists(), "kept for 30 days");

        fixture.clock().set(kept + 1);
        let later = fixture.login("admin").await?;
        assert_eq!(
            fixture.get("/ui/migrate", &later).await?.status(),
            StatusCode::OK
        );
        assert!(
            !directory(&fixture, &old)?.exists(),
            "deleted after 30 days"
        );
        Ok(())
    }

    /// W5-06: the list of a user's migrations reads only that user's runs: another
    /// run's record that cannot be read (a pipe nobody writes) does not hold it up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::disallowed_methods,
        reason = "creates a FIFO with mkfifo, which std has no safe call for"
    )]
    async fn the_list_reads_only_the_users_runs() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let own = start(&fixture, &admin).await?;
        let foreign = fixture
            .state_dir()
            .join("migrations")
            .join("1700000000-00000000000000ff");
        fs::create_dir_all(&foreign)?;
        let pipe = foreign.join("wizard.json");
        assert!(Command::new("mkfifo").arg(&pipe).status()?.success());

        let listed = timeout(Duration::from_secs(10), fixture.get("/ui/migrate", &admin)).await;
        let read = listed.is_err();
        if read {
            drop(OpenOptions::new().write(true).open(&pipe)?.write_all(b"{}"));
        }
        assert!(!read, "the list waited on another run's record");
        let page = text(listed??).await?;
        let id = own.rsplit('/').next().ok_or("no run id")?;
        assert!(page.contains(id), "{page}");
        Ok(())
    }
}
