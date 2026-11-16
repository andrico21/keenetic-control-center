//! An Apply whose request ends before the job starts leaves the target free.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::{
        flow::{apply, seed_source, to_preview, to_review},
        setup,
        support::outcome::TestResult,
    };

    /// W5-01: an Apply abandoned while kcc reads the target (the browser went away)
    /// does not keep the router claimed: another run applies to it.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_abandoned_apply_leaves_the_target_free() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let first = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &first).await?;
        let second = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &second).await?;

        let mut stall = fixture.router("ultra")?.stall();
        let path = format!("{first}/apply");
        let abandoned = fixture.post_form(&path, &admin, &[("confirm", "yes")]);
        tokio::select! {
            answered = abandoned => panic!("answered while the target was held: {:?}", answered.map(|response| response.status())),
            held = stall.held() => assert!(held, "the apply reached the target"),
        }
        drop(stall);

        let stream = apply(&fixture, &admin, &second).await?;
        assert!(stream.contains("event: done"), "{stream}");
        assert_eq!(fixture.outcomes("web.migrate_apply")?, ["started"]);
        Ok(())
    }
}
