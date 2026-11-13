//! The preview offers Apply only when the plan sends at least one command.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::{keys, locale::Locale};

    use crate::{
        en,
        plan_screens::{counts, to_file_preview, to_file_review},
        support::{Fixture, TestResult},
    };

    /// A source whose only lines no firmware can build: nothing is sent.
    const NOTHING: &str =
        "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\nsystem f4bogus-command on\n";

    /// A source with one setting the target lacks: one command is sent.
    const ONE: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge19\n description migrated-office\n!\n";

    #[tokio::test]
    async fn the_preview_offers_apply_only_with_a_command_to_send() -> TestResult {
        for (source, sent, offered) in [(NOTHING, 0, false), (ONE, 1, true)] {
            let fixture = Fixture::new().await?;
            let admin = fixture.login("admin").await?;
            let page = to_file_review(&fixture, &admin, source).await?;
            let preview = to_file_preview(&fixture, &admin, &page).await?;
            let shown = counts(&preview, Locale::En);
            assert_eq!(shown.get(1), Some(&sent), "commands to send: {preview}");
            assert_eq!(
                preview.contains(&format!("hx-post=\"{page}/apply\"")),
                offered,
                "Apply offered: {preview}"
            );
            assert_eq!(
                preview.contains(&en(keys::WEB_MIGRATE_NOTHING_TO_SEND)),
                !offered,
                "nothing to send: {preview}"
            );
        }
        Ok(())
    }
}
