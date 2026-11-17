//! A migration whose sealed passwords cannot be opened: every page that needs them
//! answers an internal error, and the apply is audited as failed, never shown or
//! recorded as if no password had been typed.

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

    use crate::{
        flow::{moved, seed_source, to_preview, to_review},
        setup,
        support::{
            outcome::TestResult,
            web::{Browser, Fixture},
        },
    };

    /// A migration at its preview whose sealed passwords no longer open.
    // NOT cancel-safe: the fixture's run files may be written after cancellation.
    async fn broken_run(fixture: &Fixture) -> TestResult<(Browser, String)> {
        seed_source(fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(fixture, &admin).await?;
        to_preview(fixture, &admin, &page).await?;
        let id = page.rsplit('/').next().ok_or("no run id")?;
        let sealed = fixture
            .state_dir()
            .join("migrations")
            .join(id)
            .join("passwords.sealed");
        fs::write(sealed, b"not a sealed file")?;
        Ok((admin, page))
    }

    /// W5-10: the preview over unopenable passwords is an internal error.
    ///
    /// It read them as none typed and showed a plan the apply then refused.
    #[tokio::test]
    async fn the_preview_over_unopenable_passwords_is_an_internal_error() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = broken_run(&fixture).await?;

        let preview = fixture.get(&page, &admin).await?;

        assert_eq!(preview.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    /// W5-10: step 5 read unopenable passwords as none typed; it is an internal error.
    #[tokio::test]
    async fn the_inputs_over_unopenable_passwords_are_an_internal_error() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = broken_run(&fixture).await?;
        let back = fixture
            .post_form(&format!("{page}/back"), &admin, &[("step", "inputs")])
            .await?;
        moved(&back, &page)?;

        let inputs = fixture.get(&page, &admin).await?;

        assert_eq!(inputs.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    /// W5-10: an apply over unopenable passwords is an internal error, audited `failed`.
    ///
    /// It was audited as `refused`, as if the plan were at fault.
    #[tokio::test]
    async fn an_apply_over_unopenable_passwords_is_audited_failed() -> TestResult {
        let fixture = setup::fixture().await?;
        let (admin, page) = broken_run(&fixture).await?;

        let applied = fixture
            .post_form(&format!("{page}/apply"), &admin, &[("confirm", "yes")])
            .await?;

        assert_eq!(applied.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            fixture.audit_flushed().await,
            0,
            "no audit entry left pending"
        );
        assert_eq!(fixture.outcomes("web.migrate_apply")?, ["failed"]);
        Ok(())
    }
}
