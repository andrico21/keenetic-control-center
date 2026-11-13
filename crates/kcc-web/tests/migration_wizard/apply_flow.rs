//! Steps 7 to 9: the apply followed live (and again after a reload), the result, the
//! commit and the report.

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

    use crate::{
        en,
        flow::{
            NEW_PASSWORD, SOURCE_PASSWORD, apply, moved, seed_source, stream, to_preview, to_review,
        },
        secrets::{absent, source_hash},
        support::{Fixture, TestResult, header_text, text},
    };

    /// The `line` events of a stream.
    fn lines(stream: &str) -> Vec<&str> {
        stream
            .split("\n\n")
            .filter(|event| event.starts_with("event: line"))
            .collect()
    }

    /// The outcomes of the audit entries of `action`, in order.
    fn outcomes(fixture: &Fixture, action: &str) -> TestResult<Vec<String>> {
        Ok(fixture
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .map(|entry| entry.outcome)
            .collect())
    }

    #[tokio::test]
    async fn the_nine_steps_end_with_the_target_committed() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let hash = source_hash(&fixture)?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let asked = fixture.post(&format!("{page}/apply"), &admin, &[]).await?;
        assert_eq!(
            header_text(&asked, "hx-retarget").as_deref(),
            Some("#dialog-content"),
            "Apply asks first"
        );
        let first = apply(&fixture, &admin, &page).await?;
        let sent = lines(&first);
        assert!(
            sent.iter().any(|line| {
                line.contains("interface Bridge19 description migrated-office")
                    && line.contains("data-outcome=\"applied\"")
            }),
            "each sent setting with the router's answer: {first}"
        );
        for event in [
            "event: heartbeat",
            "event: progress",
            "event: end",
            "event: done",
        ] {
            assert!(first.contains(event), "{event} in {first}");
        }
        assert!(
            first.contains(&en(keys::MIGRATE_APPLY_VERIFIED)),
            "verified: {first}"
        );
        let running = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            running.contains(&format!("sse-connect=\"{page}/events\"")),
            "a reload at step 7 follows the stream again: {running}"
        );
        let replayed = stream(&fixture, &admin, &page).await?;
        assert_eq!(lines(&replayed), sent, "the stream replays every line");
        moved(
            &fixture
                .post(&format!("{page}/results"), &admin, &[])
                .await?,
            &page,
        )?;
        let results = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            results.contains(&format!("hx-post=\"{page}/commit\""))
                && results.contains("?view=countdown"),
            "Commit, and the fail-safe countdown: {results}"
        );
        moved(
            &fixture.post(&format!("{page}/commit"), &admin, &[]).await?,
            &page,
        )?;
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_MIGRATE_FINISH_COMMITTED)),
            "step 9: {report}"
        );
        let saved = fixture.handle("ultra")?.startup_config_text();
        for line in ["description migrated-office", "description office-network"] {
            assert!(saved.contains(line), "{line} is saved on the target");
        }
        let download = fixture
            .get(&format!("{page}/download/report.html"), &admin)
            .await?;
        assert_eq!(download.status(), StatusCode::OK, "the report downloads");
        assert_eq!(
            outcomes(&fixture, "web.migrate_inputs")?,
            ["saved"],
            "the inputs, without a password-named parameter the audit log refuses"
        );
        assert_eq!(
            outcomes(&fixture, "web.migrate_apply")?,
            ["started"],
            "apply"
        );
        assert_eq!(
            outcomes(&fixture, "web.migrate_apply_end")?,
            ["verified"],
            "its end"
        );
        assert_eq!(
            outcomes(&fixture, "web.migrate_commit")?,
            ["done"],
            "commit"
        );
        absent(
            &fixture.state_dir(),
            &[NEW_PASSWORD, SOURCE_PASSWORD, &hash],
        )
    }

    #[tokio::test]
    async fn apply_names_missing_permissions_before_any_router_request() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let browser = fixture.login("without-write-save").await?;
        let page = to_review(&fixture, &browser).await?;
        to_preview(&fixture, &browser, &page).await?;
        let before = fixture.handle("ultra")?.request_count();

        let refused = fixture
            .post(&format!("{page}/apply"), &browser, &[("confirm", "yes")])
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
        assert_eq!(fixture.handle("ultra")?.request_count(), before);
        assert_eq!(outcomes(&fixture, "web.migrate_apply")?, ["forbidden"]);
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
            let fixture = Fixture::new().await?;
            seed_source(&fixture).await?;
            let browser = fixture.login(username).await?;
            let page = to_review(&fixture, &browser).await?;
            to_preview(&fixture, &browser, &page).await?;

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
                !preview.contains("web-migrate-apply-forbidden"),
                "{preview}"
            );
        }

        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let preview = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            preview.contains(&format!("hx-post=\"{page}/apply\"")),
            "admin can apply: {preview}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_second_apply_to_the_router_waits_for_the_first_to_finish() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let first = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &first).await?;
        let second = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &second).await?;
        let applied = apply(&fixture, &admin, &first).await?;
        assert!(
            applied.contains(&en(keys::MIGRATE_APPLY_VERIFIED)),
            "{applied}"
        );
        let busy = fixture
            .post(&format!("{second}/apply"), &admin, &[("confirm", "yes")])
            .await?;
        assert_eq!(busy.status(), StatusCode::UNPROCESSABLE_ENTITY, "refused");
        assert_eq!(
            header_text(&busy, "hx-retarget").as_deref(),
            Some("#wizard-step"),
            "shown in the step, not in the dialog"
        );
        assert!(
            text(busy)
                .await?
                .contains(&en(keys::WEB_MIGRATE_APPLY_BUSY)),
            "says why"
        );
        assert_eq!(
            outcomes(&fixture, "web.migrate_apply")?,
            ["started", "busy"]
        );
        moved(
            &fixture
                .post(&format!("{first}/results"), &admin, &[])
                .await?,
            &first,
        )?;
        moved(
            &fixture
                .post(&format!("{first}/commit"), &admin, &[])
                .await?,
            &first,
        )?;
        let changed = fixture
            .post(&format!("{second}/apply"), &admin, &[("confirm", "yes")])
            .await?;
        assert_eq!(
            changed.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "the router changed under the second plan"
        );
        assert!(
            text(changed)
                .await?
                .contains(&en(keys::WEB_MIGRATE_APPLY_CHANGED)),
            "it shows the plan made again"
        );
        Ok(())
    }
}
