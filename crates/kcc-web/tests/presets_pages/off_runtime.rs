//! The presets pages use the preset store off the runtime's worker (unix gates).

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
    use std::{fs, io, process::Command};

    use axum::http::StatusCode;
    use kcc_app::persist::StateStore;
    use kcc_testkit::blocking_gate::BlockingGate;
    use tokio::{task::yield_now, time::timeout};

    use crate::{
        flow::{DNS_LINES, capture, redirected, seed},
        setup,
        support::outcome::TestResult,
    };

    /// How long a gate waits for the runtime's answer.
    const GATE: Duration = Duration::from_secs(5);
    /// Bound on one request under test.
    const CALL: Duration = Duration::from_secs(60);
    /// How often the answering side lets the request run before it answers.
    const YIELDS: u32 = 10_000;

    /// G-22: the preset list reads and opens the records off the runtime's worker: while
    /// it waits on a record nobody wrote yet (a FIFO), the single-threaded runtime still
    /// answers.
    #[tokio::test(flavor = "current_thread")]
    async fn the_preset_list_reads_records_off_the_runtime() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let record = fixture
            .state_dir()
            .join("presets")
            .join(format!("{id}.json"));
        let bytes = fs::read(&record)?;
        fs::remove_file(&record)?;
        assert!(Command::new("mkfifo").arg(&record).status()?.success());
        let held = BlockingGate::pipe(record, bytes, GATE);

        let (listed, answered) = timeout(CALL, async {
            tokio::join!(fixture.get("/ui/presets", &admin), held.release())
        })
        .await?;

        assert_eq!(listed?.status(), StatusCode::OK);
        assert!(
            answered?,
            "the runtime was blocked while the presets were read"
        );
        Ok(())
    }

    /// G-22: saving a captured preset (the store's lock, sealing, the write) runs off the
    /// runtime's worker: while another holder keeps the presets lock, the runtime still
    /// answers.
    ///
    /// The answer comes only after the request had `YIELDS` chances to reach the lock:
    /// the request's own earlier waits (the session's reads) end within them.
    #[tokio::test(flavor = "current_thread")]
    async fn a_preset_capture_waits_for_the_lock_off_the_runtime() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let read = fixture
            .post_multipart(
                "/ui/presets/new",
                &admin,
                (&[("kind", "router"), ("router", "prod-1")], None),
            )
            .await?;
        let draft = redirected(&read)?;
        let state = StateStore::open(&fixture.state_dir())?;
        let mut held = BlockingGate::hold(
            GATE,
            move || state.lock("presets").map_err(io::Error::other),
            |lock| {
                drop(lock);
                Ok(())
            },
        );
        held.entered().await?;

        let (saved, answered) = timeout(CALL, async {
            tokio::join!(
                fixture.post_form(
                    &draft,
                    &admin,
                    &[("group", "dns-secure"), ("name", "Locked")]
                ),
                async {
                    for _ in 0..YIELDS {
                        yield_now().await;
                    }
                    held.release().await
                }
            )
        })
        .await?;

        drop(redirected(&saved?)?);
        assert!(
            answered?,
            "the runtime was blocked while the preset was saved"
        );
        Ok(())
    }
}
