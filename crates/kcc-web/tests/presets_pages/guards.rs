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
    use kcc_testkit::model::{Firmware, Profile};

    use crate::{
        flow::{DNS_LINES, apply, capture, finish, moved, redirected, seed, start, to_preview},
        setup,
        support::{
            outcome::TestResult,
            page::{en_with, text},
            web::Fixture,
        },
    };

    #[tokio::test]
    async fn a_viewer_sees_no_change_control_and_every_change_is_refused() -> TestResult {
        let fixture = setup::fixture().await?;
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
            let response = fixture.post_form(path, &viewer, &[]).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let read = fixture
            .post_multipart(
                "/ui/presets/new",
                &viewer,
                (&[("kind", "router"), ("router", "prod-1")], None),
            )
            .await?;
        assert_eq!(read.status(), StatusCode::FORBIDDEN, "no source is read");
        assert_eq!(fixture.request_counts(), before, "no router was asked");
        Ok(())
    }

    /// Parser commands `lab-1` received after the first `before` requests.
    fn commands(fixture: &Fixture, before: usize) -> TestResult<Vec<String>> {
        Ok(fixture
            .router("lab-1")?
            .request_log()
            .iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .collect())
    }

    /// The built-in operator applies a preset and keeps it unsaved or saves it: `lab-1`
    /// runs arm, the preset's lines, then disarm or commit.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_operator_applies_a_preset_and_keeps_or_saves_it() -> TestResult {
        for (way, closing) in [
            ("keep", "no system configuration fail-safe timer"),
            ("save", "system configuration fail-safe commit"),
        ] {
            let fixture = setup::fixture().await?;
            seed(&fixture, "prod-1", &DNS_LINES).await?;
            let operator = fixture.login("operator").await?;
            let id = capture(&fixture, &operator, "prod-1", (&["dns-secure"], "Office")).await?;
            let page = start(&fixture, &operator, &id).await?;
            to_preview(&fixture, &operator, &page, ("lab-1", "merge", &[])).await?;
            let before = fixture.router("lab-1")?.request_log().len();

            let stream = apply(&fixture, &operator, &page).await?;
            finish(&fixture, &operator, &page, (way, &[])).await?;

            assert!(
                stream.contains(&en_with(keys::WEB_PRESETS_APPLIED, &[])),
                "{way}: {stream}"
            );
            let sent = commands(&fixture, before)?;
            let order = [
                "system configuration fail-safe timer reboot 900",
                DNS_LINES[0],
                closing,
            ]
            .map(|line| sent.iter().rposition(|command| command == line));
            assert!(
                matches!(order, [Some(arm), Some(line), Some(closed)] if arm < line && line < closed),
                "{way}: {sent:?}"
            );
            assert!(!fixture.router("lab-1")?.recovery_armed(), "{way}");
            assert_eq!(fixture.outcomes("web.preset_apply")?, ["started"]);
            assert_eq!(fixture.outcomes(&format!("web.preset_{way}"))?, ["done"]);
        }
        Ok(())
    }

    /// The operator's rollback is refused before `lab-1` receives a request; the run stays
    /// armed for a keep or a save.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_operators_rollback_is_refused_before_any_router_request() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let operator = fixture.login("operator").await?;
        let id = capture(&fixture, &operator, "prod-1", (&["dns-secure"], "Office")).await?;
        let page = start(&fixture, &operator, &id).await?;
        to_preview(&fixture, &operator, &page, ("lab-1", "merge", &[])).await?;
        let stream = apply(&fixture, &operator, &page).await?;
        assert!(
            stream.contains(&en_with(keys::WEB_PRESETS_APPLIED, &[])),
            "{stream}"
        );
        moved(
            &fixture
                .post_form(&format!("{page}/results"), &operator, &[])
                .await?,
            &page,
        )?;
        let results = text(fixture.get(&page, &operator).await?).await?;
        assert!(
            !results.contains(&format!("hx-post=\"{page}/rollback\"")),
            "no rollback control for the operator: {results}"
        );
        let before = fixture.router("lab-1")?.request_count();

        let refused = fixture
            .post_form(
                &format!("{page}/rollback"),
                &operator,
                &[("confirm", "yes"), ("confirm_name", "lab-1")],
            )
            .await?;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(fixture.router("lab-1")?.request_count(), before);
        assert!(fixture.router("lab-1")?.recovery_armed());
        assert_eq!(fixture.outcomes("web.preset_rollback")?, ["forbidden"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_role_scoped_to_lab_cannot_touch_prod_and_sends_nothing() -> TestResult {
        let fixture = setup::fixture().await?;
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
            .post_form(&format!("/ui/presets/{id}/apply"), &scoped, &[])
            .await?;
        assert_eq!(started.status(), StatusCode::NOT_FOUND, "no run of it");
        let page = redirected(&fixture.post_form("/ui/copy", &scoped, &[]).await?)?;
        let source = fixture
            .post_form(
                &format!("{page}/source"),
                &scoped,
                &[("router", "prod-1"), ("group", "dns-secure")],
            )
            .await?;
        assert_eq!(source.status(), StatusCode::UNPROCESSABLE_ENTITY, "source");
        assert!(
            text(source)
                .await?
                .contains(&en_with(keys::WEB_MIGRATE_SOURCE_ERROR_ROUTER, &[])),
            "prod-1 is refused as the source"
        );
        assert_eq!(fixture.request_counts(), before, "no router was asked");
        assert_eq!(fixture.outcomes("web.preset_copy_source")?, ["forbidden"]);
        Ok(())
    }

    #[tokio::test]
    async fn newer_settings_are_refused_by_an_older_target() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let page = start(&fixture, &admin, &id).await?;
        let refused = fixture
            .post_form(&format!("{page}/target"), &admin, &[("router", "lab-2")])
            .await?;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let html = text(refused).await?;
        let refusal = en_with(
            keys::WEB_PRESETS_PROBLEM_FIRMWARE_OLDER,
            &[
                ("version", Firmware::V4_3.title()),
                ("value", Profile::default().firmware().title()),
            ],
        );
        assert!(
            html.contains(&refusal),
            "the localized TargetFirmwareOlder refusal: {html}"
        );
        assert_eq!(fixture.outcomes("web.preset_target")?, ["refused"]);
        moved(
            &fixture
                .post_form(&format!("{page}/target"), &admin, &[("router", "lab-1")])
                .await?,
            &page,
        )?;
        Ok(())
    }
}
