//! The one-field edit dialog: the most common domain-page form, for a host name, a
//! description, an SSID or a server address.
//!
//! The form posts to the page's action and the outcome lands in the page's outcome region
//! (`#page-outcome`); a field error comes back into the dialog as 422, with the value as
//! typed, so the user corrects it in place.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    outcome::Failure,
    respond,
    submit::{self, Invalid},
};
use crate::{
    errors,
    page::{Localize as _, Shell},
};

/// A one-field edit dialog.
#[derive(Template)]
#[template(path = "partials/kit_field_dialog.html")]
pub(crate) struct FieldDialog {
    /// Locale carrier.
    shell: Shell,
    /// Dialog title.
    dialog_title: MessageKey,
    /// Where the form posts.
    post_to: String,
    /// The field's label.
    field_label: MessageKey,
    /// Help under the field.
    field_help: Option<MessageKey>,
    /// The value shown in the field: the current one, or the one typed.
    field_value: String,
    /// Localized error under the field; empty when none.
    field_error: String,
}

localized!(FieldDialog);

impl FieldDialog {
    /// The dialog titled and labelled by `(title, label)`, posting to `post_to`.
    pub(crate) const fn new(
        shell: Shell,
        post_to: String,
        (title, label): (MessageKey, MessageKey),
    ) -> Self {
        Self {
            shell,
            dialog_title: title,
            post_to,
            field_label: label,
            field_help: None,
            field_value: String::new(),
            field_error: String::new(),
        }
    }

    /// Shows `help` under the field.
    pub(crate) const fn with_help(mut self, help: MessageKey) -> Self {
        self.field_help = Some(help);
        self
    }

    /// Fills the field with `value`.
    pub(crate) fn with_value(mut self, value: String) -> Self {
        self.field_value = value;
        self
    }

    /// Shows `error` under the field.
    pub(crate) fn with_error(mut self, error: String) -> Self {
        self.field_error = error;
        self
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        errors::render(self)
    }

    /// The dialog again with its error: 422, shown in the shared dialog.
    pub(crate) fn invalid(&self) -> Response {
        respond::in_dialog(respond::unprocessable(self))
    }
}

/// The one-field dialog answers values that failed their check, and a change the domain
/// could not plan, under its field.
impl submit::Form for FieldDialog {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let error = invalid
            .into_findings()
            .into_iter()
            .map(|(_field, rule)| tr(locale, rule, None))
            .collect::<Vec<_>>()
            .join(" ");
        self.with_error(error).invalid()
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        self.with_error(failure.message().to_owned()).invalid()
    }
}

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

    use super::FieldDialog;
    use crate::page_kit::context::fragment_shell;

    #[test]
    fn the_dialog_keeps_the_typed_value_and_names_the_error() -> Result<(), Box<dyn Error>> {
        let dialog = FieldDialog::new(
            fragment_shell(Locale::En),
            "/ui/r/home/system/general/hostname".to_owned(),
            (
                keys::WEB_SYSTEM_HOSTNAME_TITLE,
                keys::WEB_DASHBOARD_HOSTNAME,
            ),
        )
        .with_value("bad host!".to_owned())
        .with_error("Use letters.".to_owned());
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
