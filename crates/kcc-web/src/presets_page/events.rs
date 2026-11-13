//! The live progress of a run's apply: `GET /ui/presets/runs/{run}/events`.
//!
//! The migration wizard's stream (`Feed`) ending with the run's recorded end: every
//! setting sent so far (a reload replays them), each new one and the share sent, a
//! heartbeat every 10 seconds with the fail-safe countdown, then `end` and `done`.
//! `?view=countdown` sends the heartbeat only, for the results step.

use alloc::sync::Arc;

use axum::{
    Extension,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::apply::ApplyError;

use super::{
    access::Visit,
    record::{FILE, Record},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    migrate_wizard::{
        access::Services,
        beats::closing,
        events::{Ending, Feed, View},
        run::{Ended, failure_text as wizard_text},
        service::Wizards,
    },
    overview::guarded,
};

/// `GET /ui/presets/runs/{run}/events`: the apply's progress.
// cancel-safe: reads only; the returned stream owns its state.
pub(super) async fn events(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(view): Query<View>,
    Extension(runs): Extension<Arc<Wizards>>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let visit = match Visit::open(services, &runs, &id).await {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let Some(run) = visit.record().run() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(permit) = state.streams().try_acquire(&current.stream_key()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let store = services.store();
    let locale = user.locale();
    let ending: Ending = Box::new(move || {
        let ended = store
            .load_named::<Record>(&id, FILE)
            .ok()
            .flatten()
            .and_then(|record| record.run()?.ended().cloned());
        closing(
            locale,
            format!("/ui/presets/runs/{id}/results"),
            end_words(ended.as_ref(), locale),
        )
    });
    let apply = (
        visit.session().live(),
        (run.started_at(), run.safety_seconds()),
    );
    drop(visit);
    let feed = Feed::new(&state, locale, apply, ending);
    guarded(feed.stream(view.countdown()), permit).into_response()
}

/// The notice tone and sentence of an apply that ended as `ended` records (none: kcc
/// restarted while it ran).
pub(super) fn end_words(ended: Option<&Ended>, locale: Locale) -> (&'static str, String) {
    let (tone, key) = match ended {
        Some(found) if found.verified() => ("success", keys::WEB_PRESETS_APPLIED),
        Some(found) => (
            "error",
            found
                .failure()
                .map_or(keys::WEB_PRESETS_FAILURE_FAILED, recorded_text),
        ),
        None => ("error", keys::WEB_PRESETS_RUN_INTERRUPTED),
    };
    (tone, tr(locale, key, None))
}

/// The sentence explaining `failure` on a run's pages: the run's own words where they
/// differ from the wizard's.
pub(super) const fn failure_text(failure: ApplyError) -> MessageKey {
    match failure {
        ApplyError::Source => keys::WEB_PRESETS_FAILURE_SETTINGS,
        ApplyError::Cancelled => keys::WEB_PRESETS_FAILURE_CANCELLED,
        ApplyError::SameRouter
        | ApplyError::Firmware
        | ApplyError::Workflow
        | ApplyError::Job
        | ApplyError::HardwareMismatch => keys::WEB_PRESETS_FAILURE_FAILED,
        other @ (ApplyError::ReplanRequired
        | ApplyError::UnverifiedFirmwareTier
        | ApplyError::Drift
        | ApplyError::ModeUnknown
        | ApplyError::AgreementRequired
        | ApplyError::PasswordRequired
        | ApplyError::Validation
        | ApplyError::DisarmFailed
        | ApplyError::SavedDisarmFailed
        | ApplyError::ArmUnconfirmed
        | ApplyError::FinishFailed
        | ApplyError::RollbackRestarting
        | ApplyError::CommittedSaveFailed
        | ApplyError::Stopped
        | ApplyError::Verification
        | ApplyError::RolledBackByRouter
        | ApplyError::Unreachable
        | ApplyError::JobStart
        | _) => wizard_text(other),
    }
}

/// The sentence explaining the failure a record names `name`; a name this kcc does not
/// know reads as a stopped run.
pub(super) fn recorded_text(name: &str) -> MessageKey {
    ApplyError::from_name(name).map_or(keys::WEB_PRESETS_FAILURE_FAILED, failure_text)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::apply::ApplyError;

    use super::end_words;
    use crate::migrate_wizard::run::{Ended, failure_name};

    /// A run that needs a new plan says so, not that the routers drifted.
    #[test]
    fn a_run_that_needs_a_new_plan_says_so() -> Result<(), serde_json::Error> {
        let name = failure_name(ApplyError::ReplanRequired);
        let ended: Ended = serde_json::from_str(&format!(
            "{{\"at\":2,\"verified\":false,\"failure\":\"{name}\",\"applied\":0,\"failed\":0}}"
        ))?;
        let (tone, words) = end_words(Some(&ended), Locale::En);
        assert_eq!(tone, "error");
        assert_eq!(words, tr(Locale::En, keys::MIGRATE_APPLY_REPLAN, None));
        Ok(())
    }
}
