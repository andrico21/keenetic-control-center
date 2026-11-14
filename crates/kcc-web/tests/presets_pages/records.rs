//! A preset run's record written by an earlier kcc: it opens at its step and resumes.

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

    use crate::{
        setup,
        support::{outcome::TestResult, page::text, web::Fixture},
    };

    /// The id of the stored record.
    const ID: &str = "1600000000-8899aabbccddeeff";

    /// The record as an earlier kcc wrote it, at its report.
    const STORED: &str = include_str!("../fixtures/preset-run-record.json");

    /// Writes `record` as the run's `preset.json` and returns the file's path.
    fn plant(fixture: &Fixture, record: &str) -> TestResult<PathBuf> {
        let directory = fixture.state_dir().join("migrations").join(ID);
        fs::create_dir_all(&directory)?;
        let file = directory.join("preset.json");
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
    async fn an_earlier_run_record_opens_and_resumes() -> TestResult {
        let fixture = setup::fixture().await?;
        let migrator = fixture.login("migrator").await?;
        let file = plant(&fixture, STORED)?;
        let page = format!("/ui/presets/runs/{ID}");

        let report = fixture.get(&page, &migrator).await?;
        assert_eq!(report.status(), StatusCode::OK, "the report opens");
        let html = text(report).await?;
        assert!(
            html.contains("aria-current=\"step\"><span class=\"wizard-steps__number\">9</span>"),
            "at step 9"
        );
        assert!(html.contains("data-tone=\"success\""), "kept unsaved");
        assert!(html.contains("<dd>3</dd>"), "the applied count");
        assert!(html.contains("fixture-public-key-1"), "the new public key");
        assert!(
            html.contains("<p class=\"wizard-warning\" data-tone=\"warning\">"),
            "the copied private key's warning"
        );

        let review = STORED.replacen("\"step\": \"report\"", "\"step\": \"review\"", 1);
        let file_again = plant(&fixture, &review)?;
        assert_eq!(file_again, file, "the same record");
        let back = fixture
            .post_form(&format!("{page}/back"), &migrator, &[("step", "options")])
            .await?;
        assert_eq!(
            back.headers()
                .get("hx-redirect")
                .and_then(|value| value.to_str().ok()),
            Some(page.as_str()),
            "back to the options"
        );
        assert_eq!(stored_step(&file)?, "options", "the step was saved");
        Ok(())
    }

    #[tokio::test]
    async fn a_run_record_with_an_unknown_field_does_not_open() -> TestResult {
        let fixture = setup::fixture().await?;
        let migrator = fixture.login("migrator").await?;
        let unknown = STORED.replacen("\"schema\": 1,", "\"schema\": 1,\n  \"later\": true,", 1);
        drop(plant(&fixture, &unknown)?);
        let response = fixture
            .get(&format!("/ui/presets/runs/{ID}"), &migrator)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a record this kcc cannot read is refused"
        );
        Ok(())
    }
}
