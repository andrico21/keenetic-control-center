//! Preset router scope on the Web: a preset of a router outside the user's scope answers
//! every preset page exactly like a missing id and stays stored.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::fs;

    use crate::{
        flow::{DNS_LINES, capture, seed},
        setup,
        support::{
            outcome::TestResult,
            page::text,
            web::{Browser, Fixture},
        },
    };

    /// The status and body `path` answers `browser`, with `id` written as `<id>`.
    async fn answer(
        fixture: &Fixture,
        browser: &Browser,
        (post, path): (bool, &str),
        id: &str,
    ) -> TestResult<(u16, String)> {
        let response = if post {
            fixture
                .post_form(path, browser, &[("name", "x"), ("confirm", "on")])
                .await?
        } else {
            fixture.get(path, browser).await?
        };
        let status = response.status().as_u16();
        Ok((status, text(response).await?.replace(id, "<id>")))
    }

    /// E-02, G-02: the `lab-*` user asks for the page, delete dialog, delete and reveal of a
    /// `prod-1` preset and of a missing id; every answer and every audit outcome is the
    /// same, and the preset is not removed.
    #[tokio::test]
    async fn a_preset_of_another_scope_answers_like_a_missing_one() -> TestResult {
        let fixture = setup::fixture().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
        let record = fixture.state_dir().join(format!("presets/{id}.json"));
        let before = fs::read(&record)?;
        let (stamp, _random) = id.split_once('-').ok_or("an id is <time>-<random>")?;
        let missing = format!("{stamp}-0000000000000000");
        let scoped = fixture.login("scoped").await?;

        for (post, suffix) in [
            (false, ""),
            (false, "/delete"),
            (true, "/delete"),
            (true, "/reveal"),
            (false, "/apply"),
        ] {
            let stored = format!("/ui/presets/{id}{suffix}");
            let absent = format!("/ui/presets/{missing}{suffix}");
            assert_eq!(
                answer(&fixture, &scoped, (post, &stored), &id).await?,
                answer(&fixture, &scoped, (post, &absent), &missing).await?,
                "{suffix}"
            );
        }

        assert_eq!(fs::read(&record)?, before);
        assert_eq!(
            fixture.outcomes("web.preset_delete")?,
            ["refused", "refused"]
        );
        Ok(())
    }
}
