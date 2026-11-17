//! Steps 4 to 6: the review, the inputs and the preview of the plan.

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
        flow::{
            NEW_PASSWORD, SOURCE_PASSWORD, indices, seed_source, to_preview, to_review, value_of,
        },
        redirected,
        secrets::{absent, source_hash},
        setup,
        support::{
            outcome::TestResult,
            page::{current_step, en, header_text, text},
        },
    };

    #[tokio::test]
    async fn review_keeps_target_bridge_members_that_cli_and_mcp_plan() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;

        let page = to_review(&fixture, &admin).await?;
        let review = text(fixture.get(&page, &admin).await?).await?;

        for member in [
            "GigabitEthernet0/1",
            "GigabitEthernet0/2",
            "GigabitEthernet0/3",
            "GigabitEthernet0/4",
            "WifiMaster0/AccessPoint0",
        ] {
            let line = format!("interface Bridge0 include {member}");
            let start = review
                .find(&line)
                .ok_or_else(|| format!("missing {line}"))?;
            let row = review
                .get(start..)
                .and_then(|tail| tail.split_once("</tr>").map(|(row, _)| row))
                .ok_or("incomplete membership row")?;
            assert!(row.contains("data-fate=\"migrated\""), "{line}: {row}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_review_waits_for_conflicts_and_the_inputs_for_passwords() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let hash = source_hash(&fixture)?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        let review = text(fixture.get(&page, &admin).await?).await?;
        for expected in [
            "interface Bridge19 description migrated-office".to_owned(),
            en(keys::WEB_MIGRATE_FATE_CONFLICT),
            en(keys::WEB_MIGRATE_FATE_INPUT),
        ] {
            assert!(review.contains(&expected), "{expected} in {review}");
        }
        assert!(!review.contains(&hash), "the password hash is redacted");
        let refused = fixture
            .post_form(&format!("{page}/review/continue"), &admin, &[])
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unresolved"
        );
        let conflict = indices(&review, "name=\"resolve-")
            .pop()
            .ok_or("a conflict")?;
        let field = format!("resolve-{conflict}");
        let saved = fixture
            .post_form(
                &format!("{page}/review"),
                &admin,
                &[("shown", &conflict), (&field, "source")],
            )
            .await?;
        assert_eq!(
            saved.status(),
            StatusCode::NO_CONTENT,
            "saved as it changes"
        );
        let reviewed = fixture
            .post_form(&format!("{page}/review/continue"), &admin, &[])
            .await?;
        assert_eq!(redirected(&reviewed)?, page, "on to the inputs");
        let inputs = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            inputs.contains("name=\"password-0\"") && inputs.contains("type=\"password\""),
            "a write-only password field: {inputs}"
        );
        let password = inputs.find("type=\"password\"").ok_or("password input")?;
        let start = inputs
            .get(..password)
            .and_then(|before| before.rfind("<form"))
            .ok_or("inputs form")?;
        let form = inputs
            .get(start..)
            .and_then(|tail| tail.split_once('>').map(|(tag, _)| tag))
            .ok_or("inputs form")?;
        assert!(form.contains(" method=\"post\""), "native method: {form}");
        assert!(
            form.contains(&format!(" action=\"{page}/inputs\""))
                && form.contains(&format!(" hx-post=\"{page}/inputs\"")),
            "matching targets: {form}"
        );
        let reconnect = value_of(&inputs, "name=\"reconnect_url\"").ok_or("reconnect field")?;
        let user = value_of(&inputs, "name=\"user-0\"").ok_or("user field")?;
        let missing = fixture
            .post_form(
                &format!("{page}/inputs"),
                &admin,
                &[("user-0", &user), ("reconnect_url", &reconnect)],
            )
            .await?;
        assert_eq!(
            missing.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        assert!(
            text(missing)
                .await?
                .contains(&en(keys::WEB_MIGRATE_INPUTS_PASSWORD_MISSING)),
            "says why"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_preview_orders_the_plan_and_no_file_holds_a_secret() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let hash = source_hash(&fixture)?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let preview = text(fixture.get(&page, &admin).await?).await?;
        for expected in [
            "interface Bridge19 description migrated-office".to_owned(),
            "interface Bridge0 description office-network".to_owned(),
            en(keys::WEB_MIGRATE_PHASE_MANAGEMENT),
            en(keys::WEB_MIGRATE_APPLY),
        ] {
            assert!(preview.contains(&expected), "{expected} in {preview}");
        }
        for file in ["plan.json", "report.json", "report.md", "report.html"] {
            let response = fixture
                .get(&format!("{page}/download/{file}"), &admin)
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "{file}");
            assert!(
                header_text(&response, "content-disposition")
                    .is_some_and(|value| value.starts_with("attachment")),
                "{file} downloads"
            );
            let body = text(response).await?;
            for secret in [NEW_PASSWORD, SOURCE_PASSWORD, hash.as_str()] {
                assert!(!body.contains(secret), "{file} holds a secret");
            }
        }
        absent(
            &fixture.state_dir(),
            &[NEW_PASSWORD, SOURCE_PASSWORD, &hash],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn a_reload_or_a_new_session_resumes_at_the_current_step() -> TestResult {
        let fixture = setup::fixture().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = to_review(&fixture, &admin).await?;
        to_preview(&fixture, &admin, &page).await?;
        let first = text(fixture.get(&page, &admin).await?).await?;
        assert_eq!(current_step(&first), Some(6), "at the preview");
        let again = fixture.login("admin").await?;
        let resumed = text(fixture.get(&page, &again).await?).await?;
        assert_eq!(current_step(&resumed), Some(6), "a new session resumes it");
        assert!(
            resumed.contains(&en(keys::WEB_MIGRATE_PREVIEW_TITLE)),
            "with the preview"
        );
        let stranger = fixture.login("operator").await?;
        let hidden = fixture.get(&page, &stranger).await?;
        assert_eq!(hidden.status(), StatusCode::NOT_FOUND, "another account's");
        Ok(())
    }
}
