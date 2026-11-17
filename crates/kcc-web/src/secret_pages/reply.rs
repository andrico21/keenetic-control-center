//! What a secret write answers: the read-back's verdict in the outcome, or why nothing
//! was sent.

use core::future::ready;

use axum::response::{IntoResponse as _, Response};
use fluent_bundle::FluentArgs;
use kcc_domain::DomainError;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use secrecy::SecretString;

use super::{
    dialog::{Entry, REPEAT, SECRET, SecretDialog},
    user_password::protected,
};
use crate::page_kit::{
    action::Action,
    outcome::{Failure, Outcome},
    respond::changed,
    submit::{self, Invalid, unplanned::Unplanned},
};

/// A secret dialog as the form of a write.
///
/// A mismatch and a value that failed its check come back into the dialog under their
/// field, a refused plan under the new value (the account kcc signs in with as the
/// dialog's refusal), and a success says what the read-back checked. It holds no secret:
/// the typed value goes from the check to the plan only.
pub(crate) struct Secret {
    /// The dialog.
    dialog: SecretDialog,
    /// The label of the secret written.
    what: MessageKey,
    /// What a success says the read-back checked.
    done: MessageKey,
}

impl Secret {
    /// `dialog`, writing the secret labelled `what`, whose read-back checks only that a
    /// value is stored.
    pub(crate) const fn new(dialog: SecretDialog, what: MessageKey) -> Self {
        Self {
            dialog,
            what,
            done: keys::WEB_SECRET_DONE,
        }
    }

    /// `dialog`, writing the secret labelled `what`, whose read-back checks that the stored
    /// value changed.
    pub(crate) const fn replacing(dialog: SecretDialog, what: MessageKey) -> Self {
        Self {
            dialog,
            what,
            done: keys::WEB_SECRET_CHANGED,
        }
    }
}

impl submit::Form for Secret {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let Some((field, rule)) = invalid.into_findings().into_iter().next() else {
            return self.dialog.refusal().into_response();
        };
        let answer = match field {
            REPEAT => self.dialog.mismatch(),
            SECRET => self.dialog.secret_error(tr(locale, rule, None)),
            _plain => self.dialog.plain_error(tr(locale, rule, None)),
        };
        answer.into_response()
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        self.dialog
            .secret_error(failure.message().to_owned())
            .into_response()
    }

    fn answer_unplanned(
        self,
        unplanned: Unplanned<'_>,
        locale: Locale,
    ) -> impl Future<Output = Response> {
        let answer = if matches!(unplanned.error(), DomainError::ProtectedAccount) {
            self.dialog.refused(protected(locale)).refusal()
        } else {
            let failure = unplanned.into_failure();
            self.dialog.secret_error(failure.message().to_owned())
        };
        ready(answer.into_response())
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<String>,
        locale: Locale,
    ) -> Response {
        changed(
            verified(outcome, locale, (self.what, self.done)),
            refreshed,
            None,
            locale,
        )
    }
}

/// The new value typed twice, or the mismatch, at the repetition, when the two entries
/// differ; `None` when both were left empty.
pub(crate) fn typed(entry: Entry) -> Option<Result<SecretString, Invalid>> {
    match entry {
        Entry::Keep => None,
        Entry::Mismatch => Some(Err(Invalid::at(REPEAT, keys::WEB_SECRET_MISMATCH))),
        Entry::New(secret) => Some(Ok(secret)),
    }
}

/// `outcome` of writing the secret `what` (a field label); a success says, in the words of
/// `done`, what the read-back checked: a stored value, or a changed one, never which one.
pub(crate) fn verified(
    outcome: Outcome,
    locale: Locale,
    (what, done): (MessageKey, MessageKey),
) -> Outcome {
    let mut args = FluentArgs::new();
    args.set("what", tr(locale, what, None));
    confirmed(outcome, tr(locale, done, Some(&args)))
}

/// `outcome` with `headline` when it succeeded, which keeps its unsaved state.
pub(crate) fn confirmed(outcome: Outcome, headline: String) -> Outcome {
    if outcome.succeeded() {
        Outcome::done(headline, outcome.unsaved())
    } else {
        outcome
    }
}

/// Both fields were left empty: the stored value stays, nothing is sent, and the action
/// is audited as `unchanged`.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn unchanged(action: Action<'_>) -> Response {
    let locale = action.locale();
    action.abandon("unchanged").await;
    let headline = tr(locale, keys::WEB_SECRET_UNCHANGED, None);
    changed(Outcome::info(headline, "unchanged"), None, None, locale)
}
