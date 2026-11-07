//! Resuming a run at its current step, and Back.
//!
//! `GET /ui/presets/runs/{run}` shows the current step, whatever the browser did before
//! (a reload, another tab, a restart of kcc); Back shows an earlier step while choices
//! can still change.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use super::{
    access::Visit,
    apply::Running,
    inputs, options, preview, report, results,
    review::{self, View},
    screen, source,
    steps::Step,
    target,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    migrate_wizard::{access::Services, service::Wizards},
    nav::Section,
    page_kit::{
        context::{Caller, Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `GET /ui/presets/runs/{run}`: the run at its current step.
// cancel-safe: reads only.
#[expect(
    clippy::significant_drop_tightening,
    reason = "every step's panel reads the record, which lives in the visit holding the turn"
)]
pub(super) async fn page(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(view): Query<View>,
    Extension(runs): Extension<Arc<Wizards>>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Presets, None)
        .await;
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let visit = match Visit::open(services, &runs, &id).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let record = visit.record();
    match record.step() {
        Step::Source => {
            let chosen = (record.source_router(), [].as_slice());
            let panel = source::Panel::new(services, record.id(), chosen).await;
            screen::page(shell, record, &panel)
        }
        Step::Target => screen::page(shell, record, &target::Panel::new(&visit).await),
        Step::Options => screen::page(shell, record, &options::Panel::new(&visit)),
        Step::Review => screen::page(shell, record, &review::Panel::new(&visit, &view).await),
        Step::Inputs => screen::page(shell, record, &inputs::Panel::new(&visit, &[]).await),
        Step::Preview => {
            let panel = preview::Panel::new(&visit, &state).await;
            screen::page(shell, record, &panel)
        }
        Step::Apply => screen::page(shell, record, &Running::new(&visit)),
        Step::Results => screen::page(shell, record, &results::Panel::new(&visit).await),
        Step::Report => screen::page(shell, record, &report::Panel::new(&visit)),
    }
}

/// The step Back asks for.
#[derive(Debug, Deserialize)]
pub(super) struct Back {
    /// The step to show again.
    step: Step,
}

/// `POST /ui/presets/runs/{run}/back`: shows an earlier step again, when choices can
/// still change.
///
/// # Errors
///
/// Answers the refusal of the run.
// cancel-safe: reads, then one record write.
pub(super) async fn back(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(back): Form<Back>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record_mut().go_back(back.step)
        && let Err(error) = visit.save()
    {
        return Err(errors::internal(&error, fragment_shell(user.locale())).into());
    }
    Ok(screen::moved(visit.record()))
}
