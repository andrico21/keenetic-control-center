//! Another account never reaches a preset run: every route that takes a run id answers
//! 404 to it, and the owner's run stays as it was.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;

    use crate::{
        flow::{DNS_LINES, capture, seed, start, to_preview},
        setup,
        support::{
            outcome::TestResult,
            stranger::{Route, run_files, strangers_refused},
        },
    };

    /// Every route of a preset run that takes its id, as `(method, path under the run's
    /// page, form)`; an empty path is the page itself.
    const ROUTES: [Route<'static>; 21] = [
        Route::get(""),
        Route::get("/events"),
        Route::get("/download/report.json"),
        Route::get("/download/report.md"),
        Route::post("/back", &[("step", "target")]),
        Route::post("/source", &[("kind", "router"), ("router", "prod-1")]),
        Route::post("/target", &[("router", "lab-1")]),
        Route::post("/target/continue", &[("acknowledge", "yes")]),
        Route::post("/options", &[("mode", "merge")]),
        Route::post("/review", &[]),
        Route::post("/review/continue", &[]),
        Route::post("/inputs", &[]),
        Route::post("/reveal", &[]),
        Route::post("/apply", &[("confirm", "yes")]),
        Route::post("/stop", &[("confirm", "yes")]),
        Route::post("/results", &[]),
        Route::post("/keep", &[("confirm", "yes")]),
        Route::post("/save", &[("confirm", "yes")]),
        Route::post("/rollback", &[("confirm", "yes")]),
        Route::post("/retry", &[]),
        Route::post("/close", &[]),
    ];

    /// W5-17: every run route refuses another account, not only the run's page.
    ///
    /// A stranger holding `Migrate` gets 404 on every route of another account's preset run,
    /// and the owner's run (its files and its page) is unchanged.
    #[tokio::test]
    async fn every_run_route_refuses_another_account() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Owned DNS")).await?;
        let page = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let before = run_files(&fixture, &page)?;

        strangers_refused(&fixture, (&page, "migrator"), &ROUTES).await?;

        assert_eq!(run_files(&fixture, &page)?, before, "the run's files");
        let owner = fixture.get(&page, &admin).await?;
        assert_eq!(owner.status(), StatusCode::OK, "the owner still opens it");
        Ok(())
    }
}
