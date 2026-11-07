//! Copying settings once: static routes from one router to another without saving a
//! preset, finished with Save; the copied settings leave kcc when the run finishes.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::keys;

    use crate::{
        en,
        flow::{apply, finish, moved, redirected, seed, to_preview},
        support::{Fixture, TestResult, text},
    };

    /// The static route the source router has.
    const ROUTE: &str = "ip route 198.51.100.0 255.255.255.0 192.0.2.254";

    #[tokio::test]
    async fn static_routes_are_copied_once_and_saved() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture, "prod-1", &[ROUTE]).await?;
        let admin = fixture.login("admin").await?;
        let page = redirected(&fixture.post("/ui/copy", &admin, &[]).await?)?;
        moved(
            &fixture
                .post(
                    &format!("{page}/source"),
                    &admin,
                    &[("router", "prod-1"), ("group", "static-routes")],
                )
                .await?,
            &page,
        )?;
        let sealed = fixture
            .state_dir()
            .join("migrations")
            .join(page.rsplit('/').next().ok_or("run id")?)
            .join("preset.sealed");
        assert!(
            sealed.is_file(),
            "the copied settings are sealed in the run"
        );
        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = apply(&fixture, &admin, &page).await?;
        assert!(
            stream.contains(ROUTE) && stream.contains(&en(keys::WEB_PRESETS_APPLIED, &[])),
            "the route was sent and verified: {stream}"
        );
        finish(&fixture, &admin, &page, ("save", &[])).await?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_PRESETS_FINISH_SAVED, &[])),
            "step 9: {report}"
        );
        assert!(
            fixture
                .handle("lab-1")?
                .startup_config_text()
                .contains(ROUTE),
            "the route is saved on the target"
        );
        assert!(!sealed.exists(), "finishing deletes the copied settings");
        let list = text(fixture.get("/ui/presets", &admin).await?).await?;
        assert!(
            list.contains(&en(keys::WEB_PRESETS_EMPTY, &[])),
            "a copy saves no preset: {list}"
        );
        assert_eq!(fixture.outcomes("web.preset_save")?, ["done"]);
        Ok(())
    }
}
