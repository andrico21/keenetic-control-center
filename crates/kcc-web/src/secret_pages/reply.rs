//! What a secret write answers: the read-back's verdict in the outcome, or why nothing
//! was sent.

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::page_kit::{action::Action, outcome::Outcome, respond::changed};

/// `outcome` of writing the secret `what` (a field label); a success says what the
/// read-back checked: the router reports a stored value, never which one.
pub(crate) fn verified(outcome: Outcome, locale: Locale, what: MessageKey) -> Outcome {
    let mut args = FluentArgs::new();
    args.set("what", tr(locale, what, None));
    confirmed(outcome, tr(locale, keys::WEB_SECRET_DONE, Some(&args)))
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
