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
        run::Ended,
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
                .map_or(keys::WEB_PRESETS_FAILURE_FAILED, failure_text),
        ),
        None => ("error", keys::WEB_PRESETS_RUN_INTERRUPTED),
    };
    (tone, tr(locale, key, None))
}

/// The sentence explaining the engine's failure named `name`.
pub(super) fn failure_text(name: &str) -> MessageKey {
    match name {
        "DisarmFailed" => keys::MANAGEMENT_DISARM_FAILED,
        "CommittedSaveFailed" => keys::MIGRATE_COMMITTED_NOT_SAVED,
        "RollbackRestarting" => keys::MIGRATE_ROLLBACK_SAVED,
        "UnverifiedFirmwareTier" => keys::MIGRATE_APPLY_TIER,
        "ModeUnknown" => keys::MANAGEMENT_MODE_UNKNOWN,
        "Drift" | "ReplanRequired" => keys::WEB_MIGRATE_FAILURE_DRIFT,
        "Source" => keys::WEB_PRESETS_FAILURE_SETTINGS,
        "AgreementRequired" => keys::MIGRATE_APPLY_AGREEMENT,
        "PasswordRequired" => keys::WEB_MIGRATE_FAILURE_INPUT,
        "Validation" => keys::WEB_MIGRATE_FAILURE_VALIDATION,
        "Stopped" => keys::WEB_MIGRATE_FAILURE_STOPPED,
        "Verification" => keys::WEB_MIGRATE_FAILURE_VERIFICATION,
        "RolledBackByRouter" => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
        "Unreachable" => keys::WEB_MIGRATE_FAILURE_UNREACHABLE,
        "Cancelled" => keys::WEB_PRESETS_FAILURE_CANCELLED,
        "JobStart" => keys::MIGRATE_JOB_START_FAILED,
        _ => keys::WEB_PRESETS_FAILURE_FAILED,
    }
}
