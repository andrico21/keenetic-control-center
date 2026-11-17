//! How an opened action ends: the outcome it shows and the one audit record it leaves.

use kcc_i18n::{bundle::tr, locale::Locale};
use serde_json::Value;

use super::Action;
use crate::page_kit::{
    change::{Applied, Landed, Refused},
    facts::FactsError,
    family::Family,
    outcome::{Failure, Outcome},
};

/// The outcome of `action` stopped by `failure` before anything was sent, audited with
/// `params`.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn stopped(action: Action<'_>, params: Value, failure: Failure) -> Outcome {
    let outcome = Outcome::failed(failure);
    action
        .record
        .with_params(params)
        .append(action.state, action.user, outcome.audit())
        .await;
    outcome
}

/// The outcome of `action` that ended as `result`, audited with `params`.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn finished(
    action: Action<'_>,
    params: Value,
    result: Result<Landed, Refused>,
) -> Outcome {
    let locale = action.locale();
    let family = action.family;
    let outcome = match result {
        Ok(landed) => {
            let (applied, audit_pending) = landed.into_parts();
            let done = match applied {
                Applied::Terminal(_) => {
                    Outcome::done(tr(locale, family.done_terminal(), None), false)
                }
                Applied::Done { unsaved }
                | Applied::Batch {
                    applied_management_changes: _,
                    unsaved,
                    persists_immediately: _,
                    persisted_paths: _,
                    responses: _,
                }
                | Applied::Cli {
                    unsaved,
                    responses: _,
                } => Outcome::done(tr(locale, family.done(unsaved), None), unsaved),
            };
            if audit_pending {
                done.with_audit_pending(locale)
            } else {
                done
            }
        }
        Err(refused) => Outcome::failed(refused.failure(family, locale)),
    };
    action
        .record
        .with_params(params)
        .append_outcome(action.state, action.user, &outcome)
        .await;
    outcome
}

/// The failure of a router whose catalog is unknown.
pub(super) fn unknown(locale: Locale, error: FactsError) -> Failure {
    let audit = match error {
        FactsError::Unreachable => "unreachable",
        FactsError::Unsupported => "unsupported",
    };
    Failure::new(tr(locale, error.message(Family::Changes), None), audit)
}
