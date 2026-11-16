//! The audit of a migration's finish: refusals and failures are recorded, and a change the
//! router made stays audited when the record cannot be saved.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::fs;

    use axum::http::StatusCode;
    use serde_json::json;

    use crate::{
        flow::{apply, moved, seed_source, to_preview, to_review},
        setup,
        support::{outcome::TestResult, web::Fixture},
    };

    /// The id of a planted record.
    const ID: &str = "1600000000-0011223344556677";

    /// A record an earlier kcc wrote, at its report.
    const STORED: &str = include_str!("../fixtures/wizard-record.json");

    /// Plants the stored record at its results, unfinished and owned by `owner`.
    fn plant_at_results(fixture: &Fixture, owner: &str) -> TestResult {
        let record = STORED
            .replacen(
                "\"owner\": \"admin\"",
                &format!("\"owner\": \"{owner}\""),
                1,
            )
            .replacen("\"step\": \"report\"", "\"step\": \"results\"", 1)
            .replacen(
                "\"finished\": [\n    \"committed\",\n    1700000000\n  ]",
                "\"finished\": null",
                1,
            );
        let directory = fixture.state_dir().join("migrations").join(ID);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("wizard.json"), record)?;
        Ok(())
    }

    /// W2-03: a commit the router made is audited `done` although its record cannot be
    /// saved afterwards (500).
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn a_commit_stays_audited_when_its_record_cannot_be_saved() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        drop(apply(&fixture, &admin, &page).await?);
        moved(
            &fixture
                .post_form(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let run = page.rsplit('/').next().ok_or("no run id")?;
        let held = fixture
            .state_dir()
            .join("migrations")
            .join(run)
            .join("wizard.json.tmp/held");
        fs::create_dir_all(held)?;

        let committed = fixture
            .post_form(&format!("{page}/commit"), &admin, &[])
            .await?;

        assert_eq!(committed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!fixture.router("ultra")?.recovery_armed(), "committed");
        assert_eq!(fixture.outcomes("web.migrate_commit")?, ["done"]);
        Ok(())
    }

    /// W2-10: a run naming a router outside the user's `Migrate` scope is refused with an
    /// audited `forbidden` record of the run.
    // NOT cancel-safe: the fixture owns router tasks.
    #[tokio::test]
    async fn a_run_outside_the_scope_is_refused_and_audited() -> TestResult {
        let fixture = setup::fixture().await?;
        plant_at_results(&fixture, "scoped")?;
        let scoped = fixture.login("scoped").await?;

        let refused = fixture
            .post_form(&format!("/ui/migrate/{ID}/commit"), &scoped, &[])
            .await?;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let entry = fixture
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "web.migrate_run")
            .ok_or("the refusal is not audited")?;
        assert_eq!(entry.outcome, "forbidden");
        assert_eq!(entry.router.as_deref(), Some("ultra"));
        assert_eq!(entry.target.as_deref(), Some(ID));
        Ok(())
    }

    /// W2-10: a commit with no apply to finish is refused (409) with an audited record.
    // NOT cancel-safe: the fixture owns router tasks.
    #[tokio::test]
    async fn a_commit_without_a_live_apply_is_refused_and_audited() -> TestResult {
        let fixture = setup::fixture().await?;
        plant_at_results(&fixture, "admin")?;
        let admin = fixture.login("admin").await?;

        let refused = fixture
            .post_form(&format!("/ui/migrate/{ID}/commit"), &admin, &[])
            .await?;

        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let entry = fixture
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "web.migrate_commit")
            .ok_or("the refusal is not audited")?;
        assert_eq!(entry.outcome, "refused");
        assert_eq!(entry.params_redacted, json!({"reason": "conflict"}));
        Ok(())
    }
}
