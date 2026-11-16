//! A preset Apply whose request ends before the job starts leaves the target free.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::{
        flow::{DNS_LINES, apply, capture, seed, start, to_preview},
        setup,
        support::outcome::TestResult,
    };

    /// W5-01: a preset Apply abandoned while kcc reads the target does not keep the
    /// router claimed: another run applies to it.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_abandoned_apply_leaves_the_target_free() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let first = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &first, ("lab-1", "merge", &[])).await?;
        let second = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &second, ("lab-1", "merge", &[])).await?;

        let mut stall = fixture.router("lab-1")?.stall();
        let path = format!("{first}/apply");
        let abandoned = fixture.post_form(&path, &admin, &[("confirm", "yes")]);
        tokio::select! {
            answered = abandoned => panic!("answered while the target was held: {:?}", answered.map(|response| response.status())),
            held = stall.held() => assert!(held, "the apply reached the target"),
        }
        drop(stall);

        let stream = apply(&fixture, &admin, &second).await?;
        assert!(stream.contains("event: done"), "{stream}");
        assert_eq!(fixture.outcomes("web.preset_apply")?, ["started"]);
        Ok(())
    }
}
