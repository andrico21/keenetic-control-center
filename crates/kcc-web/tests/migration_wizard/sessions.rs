//! A run's in-memory side outlives other users' visits, and its apply's lease ends with
//! the router's recovery timer.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;

    use axum::http::StatusCode;
    use kcc_i18n::keys;
    use tokio::time::{advance, pause, resume};

    use crate::{
        flow::{moved, seed_source, stream, to_preview, to_review},
        setup,
        support::{
            outcome::TestResult,
            page::{en, text},
        },
    };

    /// W2-02, W5-12: while an Apply holds its run's turn, another user's visits to 64
    /// run ids that are not theirs evict nothing: the apply ends on the run's session,
    /// and its changes can be committed.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn other_users_visits_do_not_evict_a_run_in_use() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let operator = fixture.login("operator").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;

        let mut stall = fixture.router("ultra")?.stall();
        let path = format!("{page}/apply");
        let applying = fixture.post_form(&path, &admin, &[("confirm", "yes")]);
        tokio::pin!(applying);
        tokio::select! {
            answered = &mut applying => panic!("answered while the target was held: {:?}", answered.map(|response| response.status())),
            held = stall.held() => assert!(held, "the apply reached the target"),
        }
        for visit in 0_u32..65 {
            let foreign = format!("/ui/migrate/1700000000-{visit:016x}");
            let response = fixture.get(&foreign, &operator).await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{foreign}");
        }
        drop(stall);
        moved(&applying.await?, &page)?;
        let events = stream(&fixture, &admin, &page).await?;
        assert!(events.contains("event: done"), "{events}");
        moved(
            &fixture
                .post_form(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let committed = fixture
            .post_form(&format!("{page}/commit"), &admin, &[])
            .await?;
        assert_eq!(committed.status(), StatusCode::OK, "kept, not 409");
        moved(&committed, &page)?;
        Ok(())
    }

    /// E-03: an applied migration nobody finishes holds the router only as long as the
    /// router's recovery timer runs: then the run ends as rolled back by the router and
    /// the target is free for another run.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_unfinished_apply_ends_with_the_recovery_timer() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let first = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &first).await?;
        let second = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &second).await?;
        moved(
            &fixture
                .post_form(&format!("{first}/apply"), &admin, &[("confirm", "yes")])
                .await?,
            &first,
        )?;
        let events = stream(&fixture, &admin, &first).await?;
        assert!(events.contains("event: done"), "{events}");

        pause();
        advance(Duration::from_secs(15 * 60 + 2)).await;
        resume();

        let busy = fixture
            .post_form(&format!("{second}/apply"), &admin, &[("confirm", "yes")])
            .await?;
        assert_eq!(busy.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            fixture.outcomes("web.migrate_apply")?,
            ["started", "changed"],
            "the target is no longer claimed"
        );
        let report = text(fixture.get(&first, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::MIGRATE_APPLY_ROUTER_ROLLBACK)),
            "{report}"
        );
        Ok(())
    }
}
