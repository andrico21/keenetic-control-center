//! The guards around presets.
//!
//! A viewer sees no create, apply or delete control and every change is refused; a role
//! scoped to `lab-*` cannot see or use what comes from `prod-1`, and the routers receive
//! nothing; an older target refuses newer settings.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::keys;

    use crate::{
        en,
        flow::{DNS_LINES, capture, moved, redirected, seed, start},
        support::{Fixture, TestResult, text},
    };

    #[tokio::test]
    async fn a_viewer_sees_no_change_control_and_every_change_is_refused() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let viewer = fixture.login("viewer").await?;
        let list = text(fixture.get("/ui/presets", &viewer).await?).await?;
        assert!(list.contains("Office DNS"), "a viewer reads the list");
        for control in ["/ui/presets/new", "/ui/copy", "/apply", "/delete"] {
            assert!(!list.contains(control), "no {control} for a viewer: {list}");
        }
        let detail = text(fixture.get(&format!("/ui/presets/{id}"), &viewer).await?).await?;
        assert!(
            detail.contains(DNS_LINES[0]) && !detail.contains("/reveal"),
            "the redacted settings, without Reveal or Apply: {detail}"
        );
        let before = fixture.request_counts();
        let posts = [
            format!("/ui/presets/{id}/apply"),
            format!("/ui/presets/{id}/reveal"),
            format!("/ui/presets/{id}/delete"),
            "/ui/copy".to_owned(),
        ];
        for path in &posts {
            let response = fixture.post(path, &viewer, &[]).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let read = fixture
            .post_multipart(
                "/ui/presets/new",
                &viewer,
                &[("kind", "router"), ("router", "prod-1")],
            )
            .await?;
        assert_eq!(read.status(), StatusCode::FORBIDDEN, "no source is read");
        assert_eq!(fixture.request_counts(), before, "no router was asked");
        Ok(())
    }

    #[tokio::test]
    async fn a_role_scoped_to_lab_cannot_touch_prod_and_sends_nothing() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let scoped = fixture.login("scoped").await?;
        let before = fixture.request_counts();
        let list = text(fixture.get("/ui/presets", &scoped).await?).await?;
        assert!(
            !list.contains("Office DNS"),
            "the prod-1 preset is not listed"
        );
        for path in [
            format!("/ui/presets/{id}"),
            format!("/ui/presets/{id}/apply"),
        ] {
            let page = fixture.get(&path, &scoped).await?;
            assert_eq!(page.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let started = fixture
            .post(&format!("/ui/presets/{id}/apply"), &scoped, &[])
            .await?;
        assert_eq!(started.status(), StatusCode::NOT_FOUND, "no run of it");
        let page = redirected(&fixture.post("/ui/copy", &scoped, &[]).await?)?;
        let source = fixture
            .post(
                &format!("{page}/source"),
                &scoped,
                &[("router", "prod-1"), ("group", "dns-secure")],
            )
            .await?;
        assert_eq!(source.status(), StatusCode::UNPROCESSABLE_ENTITY, "source");
        assert!(
            text(source)
                .await?
                .contains(&en(keys::WEB_MIGRATE_SOURCE_ERROR_ROUTER, &[])),
            "prod-1 is refused as the source"
        );
        assert_eq!(fixture.request_counts(), before, "no router was asked");
        assert_eq!(fixture.outcomes("web.preset_copy_source")?, ["forbidden"]);
        Ok(())
    }

    #[tokio::test]
    async fn newer_settings_are_refused_by_an_older_target() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let page = start(&fixture, &admin, &id).await?;
        let refused = fixture
            .post(&format!("{page}/target"), &admin, &[("router", "lab-2")])
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let html = text(refused).await?;
        assert!(
            html.contains("The router runs firmware 4.3")
                && html.contains("older than the settings"),
            "the localized TargetFirmwareOlder refusal: {html}"
        );
        assert_eq!(fixture.outcomes("web.preset_target")?, ["refused"]);
        moved(
            &fixture
                .post(&format!("{page}/target"), &admin, &[("router", "lab-1")])
                .await?,
            &page,
        )?;
        Ok(())
    }
}
