//! How a dialog form answers a submitted change it could not take.

use axum::response::Response;
use kcc_i18n::locale::Locale;

use super::{FormDialog, Refusal};
use crate::page_kit::{
    outcome::{Failure, Outcome},
    respond,
    submit::{Form, Invalid},
};

/// The dialog answers values that failed their check under their inputs, and a change
/// the domain could not plan where the page asked for it.
impl Form for FormDialog {
    fn answer_invalid(self, invalid: Invalid, _locale: Locale) -> Response {
        self.errors(&invalid.into_findings()).invalid()
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        match self.refusal {
            Refusal::Region => respond::changed(Outcome::failed(failure), None, None, locale),
            Refusal::Field(field) => self
                .with_error(field, failure.message().to_owned())
                .invalid(),
            Refusal::Problem => self.problem(failure.message().to_owned()).invalid(),
        }
    }
}
