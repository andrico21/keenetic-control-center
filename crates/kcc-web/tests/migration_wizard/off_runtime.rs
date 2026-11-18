//! A wizard page reads the run's files off the runtime's worker (unix: a FIFO gate).

#[cfg(test)]
#[cfg(unix)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;
    use std::{fs, process::Command};

    use axum::http::StatusCode;
    use kcc_testkit::blocking_gate::BlockingGate;
    use tokio::time::timeout;

    use crate::{setup, start, support::outcome::TestResult};

    /// W2-08, W5-05: opening a migration reads its record off the runtime's worker:
    /// while the read waits on a record nobody wrote yet (a FIFO), the single-threaded
    /// runtime still answers.
    #[tokio::test(flavor = "current_thread")]
    #[expect(
        clippy::disallowed_methods,
        reason = "creates a FIFO with mkfifo, which std has no safe call for"
    )]
    async fn a_wizard_page_reads_its_record_off_the_runtime() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = start(&fixture, &admin).await?;
        let id = page.rsplit('/').next().ok_or("no run id")?;
        let record = fixture
            .state_dir()
            .join("migrations")
            .join(id)
            .join("wizard.json");
        let bytes = fs::read(&record)?;
        fs::remove_file(&record)?;
        assert!(Command::new("mkfifo").arg(&record).status()?.success());
        let held = BlockingGate::pipe(record, bytes, Duration::from_secs(5));

        let (shown, answered) = timeout(Duration::from_secs(60), async {
            tokio::join!(fixture.get(&page, &admin), held.release())
        })
        .await?;

        assert_eq!(shown?.status(), StatusCode::OK);
        assert!(
            answered?,
            "the runtime was blocked while the record was read"
        );
        Ok(())
    }
}
