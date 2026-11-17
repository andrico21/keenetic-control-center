//! A migration record written by an earlier kcc: it opens at its step, lists, and resumes.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::{fs, path::PathBuf};

    use axum::http::StatusCode;
    use kcc_i18n::keys;

    use crate::{
        setup,
        support::{
            outcome::TestResult,
            page::{current_step, en, facts, notice_tones, text},
            web::Fixture,
        },
    };

    /// The id of the stored record.
    const ID: &str = "1600000000-0011223344556677";

    /// The record as an earlier kcc wrote it, at its report.
    const STORED: &str = include_str!("../fixtures/wizard-record.json");

    /// Writes `record` as the migration's `wizard.json` and returns the file's path.
    fn plant(fixture: &Fixture, record: &str) -> TestResult<PathBuf> {
        let directory = fixture.state_dir().join("migrations").join(ID);
        fs::create_dir_all(&directory)?;
        let file = directory.join("wizard.json");
        fs::write(&file, record)?;
        Ok(file)
    }

    /// The `step` the record in `file` is at.
    fn stored_step(file: &PathBuf) -> TestResult<String> {
        let record: serde_json::Value = serde_json::from_slice(&fs::read(file)?)?;
        Ok(record
            .get("step")
            .and_then(serde_json::Value::as_str)
            .ok_or("no step")?
            .to_owned())
    }

    #[tokio::test]
    async fn an_earlier_record_opens_lists_and_resumes() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let file = plant(&fixture, STORED)?;
        let page = format!("/ui/migrate/{ID}");

        let report = fixture.get(&page, &admin).await?;
        assert_eq!(report.status(), StatusCode::OK, "the report opens");
        let html = text(report).await?;
        assert_eq!(current_step(&html), Some(9), "at step 9");
        assert_eq!(notice_tones(&html), ["success"], "a committed finish");
        let applied = (en(keys::WEB_MIGRATE_COUNT_APPLIED), "3".to_owned());
        assert!(facts(&html).contains(&applied), "the applied count");
        let list = text(fixture.get("/ui/migrate", &admin).await?).await?;
        assert!(list.contains(&page), "listed for its owner");

        let review = STORED.replacen("\"step\": \"report\"", "\"step\": \"review\"", 1);
        let file_again = plant(&fixture, &review)?;
        assert_eq!(file_again, file, "the same record");
        let back = fixture
            .post_form(&format!("{page}/back"), &admin, &[("step", "mapping")])
            .await?;
        assert_eq!(
            back.headers()
                .get("hx-redirect")
                .and_then(|value| value.to_str().ok()),
            Some(page.as_str()),
            "back to the maps"
        );
        assert_eq!(stored_step(&file)?, "mapping", "the step was saved");
        Ok(())
    }

    #[tokio::test]
    async fn a_record_with_an_unknown_field_does_not_open() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let unknown = STORED.replacen("\"schema\": 1,", "\"schema\": 1,\n  \"later\": true,", 1);
        drop(plant(&fixture, &unknown)?);
        let response = fixture.get(&format!("/ui/migrate/{ID}"), &admin).await?;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a record this kcc cannot read is refused"
        );
        Ok(())
    }
}
