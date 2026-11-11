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
    use kcc_i18n::keys;
    use kcc_testkit::FaultInjection;
    use serde_json::{Value, json};

    use crate::{
        en,
        flow::{DNS_LINES, apply, capture, finish, last_change, seed, start, to_preview},
        support::{Fixture, TestResult, header_text, text},
    };

    /// A refused keep leaves the run unfinished and reports its armed recovery timer.
    // NOT cancel-safe: the fixture applies router settings before the failed finish.
    #[tokio::test]
    async fn refused_keep_reports_armed_recovery() -> TestResult {
        let fixture =
            Fixture::with_faults(FaultInjection::default().fail_parse_matching("no system", 1))
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
        assert!(stream.contains(&en(keys::WEB_PRESETS_APPLIED, &[])));
        let results = fixture
            .post(&format!("{page}/results"), &admin, &[])
            .await?;
        assert_eq!(results.status(), StatusCode::OK);

        let response = fixture.post(&format!("{page}/keep"), &admin, &[]).await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = text(response).await?;
        assert!(
            body.contains(&en(keys::MANAGEMENT_DISARM_FAILED, &[])),
            "{body}"
        );
        assert!(fixture.handle("lab-1")?.recovery_armed());
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
        let fixture = Fixture::new().await?;
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
        let asked = fixture.post(&format!("{page}/apply"), &admin, &[]).await?;
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
            stream.contains(&en(keys::WEB_PRESETS_APPLIED, &[])),
            "verified: {stream}"
        );
        finish(&fixture, &admin, &page, ("keep", &[])).await?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_PRESETS_FINISH_KEPT, &[])),
            "step 9: {report}"
        );
        let target = fixture.handle("lab-1")?;
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
}
