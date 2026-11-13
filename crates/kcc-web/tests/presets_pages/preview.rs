//! The preview offers Apply only when the plan sends at least one command.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::keys;

    use crate::{
        en,
        flow::{DNS_LINES, capture, seed, start, to_preview},
        support::{Fixture, TestResult, text},
    };

    #[tokio::test]
    async fn the_preview_offers_apply_only_with_a_command_to_send() -> TestResult {
        for (target_lines, sent, offered) in [(&DNS_LINES[..], "0", false), (&[][..], "2", true)] {
            let fixture = Fixture::new().await?;
            seed(&fixture, "prod-1", &DNS_LINES).await?;
            seed(&fixture, "lab-1", target_lines).await?;
            let admin = fixture.login("admin").await?;
            let id = capture(&fixture, &admin, "prod-1", (&["dns-secure"], "Office DNS")).await?;
            let page = start(&fixture, &admin, &id).await?;
            to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;
            let preview = text(fixture.get(&page, &admin).await?).await?;
            let commands = format!(
                "<dt>{}</dt><dd>{sent}</dd>",
                en(keys::WEB_MIGRATE_COUNT_COMMANDS, &[])
            );
            assert!(preview.contains(&commands), "{commands}: {preview}");
            assert_eq!(
                preview.contains(&format!("hx-post=\"{page}/apply\"")),
                offered,
                "Apply offered: {preview}"
            );
            assert_eq!(
                preview.contains(&en(keys::WEB_MIGRATE_NOTHING_TO_SEND, &[])),
                !offered,
                "nothing to send: {preview}"
            );
        }
        Ok(())
    }
}
