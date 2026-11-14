//! The dialog form engine: what a dialog shows when a value comes back refused.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use askama::Template as _;
    use kcc_i18n::{keys, locale::Locale};

    use crate::page_kit::form::{FormDialog, Input};

    /// A one-field dialog keeps the typed value, names its error and answers 422 into
    /// the shared dialog.
    #[test]
    fn the_dialog_keeps_the_typed_value_and_names_the_error() -> Result<(), Box<dyn Error>> {
        let dialog = FormDialog::new(
            Locale::En,
            keys::WEB_SYSTEM_HOSTNAME_TITLE,
            "/ui/r/home/system/general/hostname".to_owned(),
        )
        .with_input(
            Input::field(
                "value",
                keys::WEB_DASHBOARD_HOSTNAME,
                "bad host!".to_owned(),
            )
            .id("kit-field"),
        )
        .with_error("value", "Use letters.".to_owned());
        let html = dialog.render()?;
        for expected in [
            "hx-post=\"/ui/r/home/system/general/hostname\" hx-target=\"#page-outcome\"",
            "value=\"bad host!\"",
            "aria-invalid=\"true\"",
            "<p class=\"field__error\" id=\"kit-field-error\">Use letters.</p>",
        ] {
            assert!(html.contains(expected), "missing {expected} in {html}");
        }
        let response = dialog.invalid();
        assert_eq!(response.status().as_u16(), 422, "field error");
        assert_eq!(
            response
                .headers()
                .get("hx-retarget")
                .and_then(|value| value.to_str().ok()),
            Some("#dialog-content"),
            "back into the dialog"
        );
        Ok(())
    }
}
