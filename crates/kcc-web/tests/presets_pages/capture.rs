//! A new preset from a router: its groups with counts, the redacted captured settings,
//! the saved preset in the list and on its own page.

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
        flow::{DNS_LINES, redirected, seed},
        support::{Fixture, TestResult, text},
    };

    #[tokio::test]
    async fn a_dns_secure_preset_is_captured_from_a_router() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture, "prod-1", &DNS_LINES).await?;
        let admin = fixture.login("admin").await?;
        let form = text(fixture.get("/ui/presets/new", &admin).await?).await?;
        assert!(
            form.contains("hx-post=\"/ui/presets/new\""),
            "the source form posts to the new preset: {form}"
        );
        let read = fixture
            .post_multipart(
                "/ui/presets/new",
                &admin,
                &[("kind", "router"), ("router", "prod-1")],
            )
            .await?;
        let draft = redirected(&read)?;
        let groups = text(fixture.get(&draft, &admin).await?).await?;
        let counted = en(keys::WEB_PRESETS_GROUP_COUNT, &[("count", "2")]);
        assert!(
            groups.contains("value=\"dns-secure\"")
                && groups.contains(&format!(
                    "Secure DNS <span class=\"presets-group__count\">{counted}</span>"
                )),
            "every group with how many settings it takes: {groups}"
        );
        let preview = text(
            fixture
                .post(
                    &format!("{draft}/preview"),
                    &admin,
                    &[("group", "dns-secure")],
                )
                .await?,
        )
        .await?;
        for line in DNS_LINES {
            assert!(preview.contains(line), "{line} is captured: {preview}");
        }
        let unnamed = fixture
            .post(&draft, &admin, &[("group", "dns-secure")])
            .await?;
        assert_eq!(
            unnamed.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a preset needs a name"
        );
        assert!(
            text(unnamed)
                .await?
                .contains(&en(keys::WEB_PRESETS_ERROR_NAME, &[])),
            "says why"
        );
        let saved = fixture
            .post(
                &draft,
                &admin,
                &[("group", "dns-secure"), ("name", "Office DNS")],
            )
            .await?;
        let page = redirected(&saved)?;
        let detail = text(fixture.get(&page, &admin).await?).await?;
        for line in DNS_LINES {
            assert!(detail.contains(line), "{line} on the preset's page");
        }
        let list = text(fixture.get("/ui/presets", &admin).await?).await?;
        assert!(
            list.contains(&format!("<a href=\"{page}\">Office DNS</a>")),
            "listed: {list}"
        );
        assert_eq!(fixture.outcomes("web.preset_source")?, ["read"]);
        assert_eq!(fixture.outcomes("web.preset_capture")?, ["saved"]);
        Ok(())
    }
}
