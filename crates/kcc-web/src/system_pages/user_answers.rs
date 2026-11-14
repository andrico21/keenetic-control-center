//! How the router-account dialog answers a submitted change: values that failed their
//! check, and a change the domain refused, come back into it under their field.

use core::future::ready;

use axum::response::{IntoResponse as _, Response};
use kcc_i18n::{bundle::tr, locale::Locale};

use super::{
    user_dialog::{Field, UserDialog},
    user_forms::refusal_message,
};
use crate::page_kit::{
    outcome::Failure,
    submit::{self, Invalid, unplanned::Unplanned},
};

impl Field {
    /// Every field, the account name first.
    const ALL: [Self; 3] = [Self::Name, Self::Tags, Self::Password];

    /// The form field it names.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Tags => "tag",
            Self::Password => "secret",
        }
    }
}

/// The account dialog as the form of a change.
///
/// Values that failed their check come back into it under their field, a change the
/// domain refused under `field`, in the words of the domain's refusal.
pub(crate) struct UserForm {
    /// The dialog.
    dialog: UserDialog,
    /// Where a refused change is shown.
    field: Field,
}

impl UserForm {
    /// `dialog`, showing a refused change under `field`.
    pub(crate) const fn new(dialog: UserDialog, field: Field) -> Self {
        Self { dialog, field }
    }
}

impl submit::Form for UserForm {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let (field, message) = invalid.into_findings().into_iter().next().map_or_else(
            || (self.field, String::new()),
            |(name, rule)| {
                let field = Field::ALL
                    .into_iter()
                    .find(|field| field.name() == name)
                    .unwrap_or(Field::Name);
                (field, tr(locale, rule, None))
            },
        );
        self.dialog.refused(field, message).into_response()
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        self.dialog
            .refused(self.field, failure.message().to_owned())
            .into_response()
    }

    fn answer_unplanned(
        self,
        unplanned: Unplanned<'_>,
        locale: Locale,
    ) -> impl Future<Output = Response> {
        let message = refusal_message(unplanned.error(), locale);
        ready(self.dialog.refused(self.field, message).into_response())
    }
}
