//! Step 8's choices that send nothing to the router.
//!
//! Plan again from the maps (a migration whose apply needs a new plan), back to the
//! preview after an apply that changed nothing, or finish once nothing waits for a
//! choice.

use alloc::sync::Arc;

use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};

use super::{
    finishing::{Finishing, Settle},
    screen,
    service::Wizards,
    services::Services,
    visit::Visit,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `POST {PREFIX}/{id}/{replan,retry,close}`: settles the run without the router.
///
/// Plans again from the maps (after components were installed), returns to the preview
/// (nothing changed), or finishes an apply with no changes to keep; another way is 404
/// once the run is at step 8.
///
/// # Errors
///
/// Answers the refusal of the run, 409 while changes wait for a choice, and 404 for
/// another way.
// cancel-safe: every change comes after the last await.
pub(crate) async fn way<F>(
    State(state): State<WebState>,
    Path((id, way)): Path<(String, String)>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let how = match way.as_str() {
        "replan" => Some(Settle::Replan),
        "retry" => Some(Settle::Retry),
        "close" => Some(Settle::Close),
        _ => None,
    };
    settle(&state, &wizards, &user, (&id, how)).await
}

/// Settles run `id` as `how` (none: a way the wizard does not know, 404).
///
/// # Errors
///
/// Answers the refusal of the run, 409 while changes wait for a choice, and 404 for no
/// `how`.
// cancel-safe: every change comes after the last await.
pub(crate) async fn settle<F>(
    state: &WebState,
    wizards: &Wizards<F>,
    user: &CurrentUser,
    (id, how): (&str, Option<Settle>),
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let services = Services::of(state, user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, wizards, id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::RESULTS {
        return Ok(screen::moved(visit.record()));
    }
    let session = visit.session();
    let pending = match session.live() {
        Some(live) => live
            .applier()
            .await
            .as_ref()
            .map(|applier| applier.report().finished),
        None => None,
    };
    if pending == Some(false) {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    let target = visit.record().target().unwrap_or_default().to_owned();
    match how {
        Some(Settle::Replan) => {
            session.forget();
            visit.record_mut().plan_anew(true);
        }
        Some(Settle::Retry) => visit.record_mut().plan_anew(false),
        Some(Settle::Close) => {
            let finished = if pending == Some(true) {
                F::ROLLED_BACK_BY_ROUTER
            } else {
                F::CLOSED
            };
            visit.record_mut().finish(finished, state.unix_seconds());
        }
        None => return Err(StatusCode::NOT_FOUND.into_response().into()),
    }
    session.set_live(None);
    wizards.release(&target, id);
    visit
        .save()
        .await
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    if how == Some(Settle::Close) {
        F::discard(services, id).await;
    }
    Ok(screen::moved(visit.record()))
}
