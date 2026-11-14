//! Applying a preset through the nine steps: Merge onto another router, followed live,
//! kept running unsaved, with the report.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_testkit::FaultInjection;
    use serde_json::{Value, json};

    use crate::{
        flow::{DNS_LINES, apply, capture, finish, last_change, seed, start, to_preview},
        setup,
        support::{
            outcome::TestResult,
            page::{en_with, header_text, text},
        },
    };

    /// A refused keep leaves the run unfinished and reports its armed recovery timer.
    // NOT cancel-safe: the fixture applies router settings before the failed finish.
    #[tokio::test]
    async fn refused_keep_reports_armed_recovery() -> TestResult {
        let fixture =
            setup::with_faults(FaultInjection::default().fail_parse_matching("no system", 1))
                .await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(
            &fixture,
            &admin,
            "prod-1",
            (&["dns-secure"], "Recovery DNS"),
        )
        .await?;
        let page = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let stream = apply(&fixture, &admin, &page).await?;
        assert!(stream.contains(&en_with(keys::WEB_PRESETS_APPLIED, &[])));
        let results = fixture
            .post_form(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);

        let response = fixture
            .post_form(&format!("{page}/keep"), &admin, &[])
            .await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = text(response).await?;
        assert!(
            body.contains(&en_with(keys::MANAGEMENT_DISARM_FAILED, &[])),
            "{body}"
        );
        assert!(fixture.router("lab-1")?.recovery_armed());
        assert_eq!(fixture.outcomes("web.preset_keep")?, ["failed"]);
        let audit = fixture.audit()?;
        let failed = audit
            .iter()
            .find(|entry| entry.action == "web.preset_keep")
            .ok_or("missing keep audit")?;
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            Some(&json!(true))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_preset_applies_in_merge_mode_and_stays_unsaved() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let page = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let preview = text(fixture.get(&page, &admin).await?).await?;
        for line in DNS_LINES {
            assert!(
                preview.contains(line),
                "{line} is in the preview: {preview}"
            );
        }
        let asked = fixture
            .post_form(&format!("{page}/apply"), &admin, &[])
            .await?;
        assert_eq!(
            header_text(&asked, "hx-retarget").as_deref(),
            Some("#dialog-content"),
            "Apply asks first"
        );
        let stream = apply(&fixture, &admin, &page).await?;
        for line in DNS_LINES {
            assert!(
                stream.contains(line) && stream.contains("data-outcome=\"applied\""),
                "{line} was sent and taken: {stream}"
            );
        }
        assert!(
            stream.contains(&en_with(keys::WEB_PRESETS_APPLIED, &[])),
            "verified: {stream}"
        );
        finish(&fixture, &admin, &page, ("keep", &[])).await?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en_with(keys::WEB_PRESETS_FINISH_KEPT, &[])),
            "step 9: {report}"
        );
        let target = fixture.router("lab-1")?;
        for line in DNS_LINES {
            assert!(target.running_config_text().contains(line), "{line} runs");
            assert!(
                !target.startup_config_text().contains(line),
                "{line} is not saved"
            );
        }
        let state = last_change(&fixture, "lab-1").await?;
        assert_eq!(
            state.pointer("/fail-safe/active"),
            Some(&Value::Bool(false)),
            "the fail-safe timer is disarmed: {state}"
        );
        assert_eq!(state.get("unsaved"), Some(&Value::Bool(true)), "unsaved");
        let download = fixture
            .get(&format!("{page}/download/report.json"), &admin)
            .await?;
        assert_eq!(download.status(), StatusCode::OK, "the report downloads");
        let json: Value = serde_json::from_str(&text(download).await?)?;
        assert_eq!(json.get("finished"), Some(&Value::from("kept-unsaved")));
        assert_eq!(fixture.outcomes("web.preset_apply")?, ["started"]);
        assert_eq!(fixture.outcomes("web.preset_apply_end")?, ["verified"]);
        assert_eq!(fixture.outcomes("web.preset_keep")?, ["done"]);
        Ok(())
    }

    #[tokio::test]
    async fn apply_names_missing_permissions_before_any_router_request() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let browser = fixture.login("without-write-save").await?;
        let id = capture(
            &fixture,
            &browser,
            "prod-1",
            (&["dns-secure"], "Recovery gate"),
        )
        .await?;
        let page = start(&fixture, &browser, &id).await?;
        to_preview(&fixture, &browser, &page, ("lab-1", "merge", &[])).await?;
        let before = fixture.router("lab-1")?.request_count();

        let refused = fixture
            .post_form(&format!("{page}/apply"), &browser, &[("confirm", "yes")])
            .await?;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            refused
                .headers()
                .get("hx-retarget")
                .and_then(|value| value.to_str().ok()),
            Some("#wizard-step")
        );
        let body = text(refused).await?;
        let named = |key| body.contains(&tr(Locale::Kk, key, None));
        assert!(
            named(keys::WEB_ADMIN_PERMISSION_WRITE)
                && named(keys::WEB_ADMIN_PERMISSION_SAVE)
                && !named(keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE),
            "the refusal names the missing permissions: {body}"
        );
        assert_eq!(fixture.router("lab-1")?.request_count(), before);
        assert_eq!(fixture.outcomes("web.preset_apply")?, ["forbidden"]);
        Ok(())
    }

    #[tokio::test]
    async fn preview_names_each_missing_apply_permission_in_the_users_locale() -> TestResult {
        for (username, locale, missing, held) in [
            (
                "without-save",
                Locale::Ru,
                &[keys::WEB_ADMIN_PERMISSION_SAVE][..],
                &[keys::WEB_ADMIN_PERMISSION_WRITE][..],
            ),
            (
                "without-write-save",
                Locale::Kk,
                &[
                    keys::WEB_ADMIN_PERMISSION_WRITE,
                    keys::WEB_ADMIN_PERMISSION_SAVE,
                ][..],
                &[][..],
            ),
        ] {
            let fixture = setup::fixture().await?;
            seed(&fixture, "prod-1", &DNS_LINES).await?;
            let browser = fixture.login(username).await?;
            let id = capture(
                &fixture,
                &browser,
                "prod-1",
                (&["dns-secure"], "Permission notice"),
            )
            .await?;
            let page = start(&fixture, &browser, &id).await?;
            to_preview(&fixture, &browser, &page, ("lab-1", "merge", &[])).await?;

            let preview = text(fixture.get(&page, &browser).await?).await?;

            for key in missing {
                let label = tr(locale, *key, None);
                assert!(
                    preview.contains(&label),
                    "{username} lacks {label}: {preview}"
                );
            }
            for key in held {
                let label = tr(locale, *key, None);
                assert!(
                    !preview.contains(&label),
                    "{username} holds {label}: {preview}"
                );
            }
            assert!(
                !preview.contains(&format!("hx-post=\"{page}/apply\"")),
                "Apply stays hidden: {preview}"
            );
            assert!(
                !preview.contains("web-presets-apply-forbidden"),
                "{preview}"
            );
        }

        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(
            &fixture,
            &admin,
            "prod-1",
            (&["dns-secure"], "Admin permission"),
        )
        .await?;
        let page = start(&fixture, &admin, &id).await?;
        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
        let preview = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            preview.contains(&format!("hx-post=\"{page}/apply\"")),
            "admin can apply: {preview}"
        );
        Ok(())
    }
}
