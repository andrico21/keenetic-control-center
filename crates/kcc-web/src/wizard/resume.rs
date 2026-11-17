//! Resuming a run at its current step, Back, and the result once the apply ended.
//!
//! `GET {PREFIX}/{id}` shows the current step, whatever the browser did before (a
//! reload, another tab, a restart of kcc); Back shows an earlier step while choices can
//! still change.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use serde::Deserialize;

use super::{flow::Flow, screen, service::Wizards, services::Services, visit::Visit};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page_kit::{
        context::{Caller, Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `GET {PREFIX}/{id}`: the run at its current step.
// cancel-safe: reads only.
pub(crate) async fn page<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(view): Query<F::View>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response
where
    F: Flow,
{
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, F::SECTION, None)
        .await;
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let visit = match Visit::open(services, &wizards, &id).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    F::show(&visit, shell, (&view, &state)).await
}

/// The step Back asks for.
#[derive(Debug, Deserialize)]
pub(crate) struct Back<S> {
    /// The step to show again.
    step: S,
}

/// `POST {PREFIX}/{id}/back`: shows an earlier step again, when choices can still
/// change; the choices stay until that step is submitted differently.
///
/// # Errors
///
/// Answers the refusal of the run.
// cancel-safe: reads, then one record write.
pub(crate) async fn back<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
    Form(back): Form<Back<F::Step>>,
) -> Result<Response, Answer>
where
    F: Flow,
{
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record_mut().go_back(back.step)
        && let Err(error) = visit.save().await
    {
        return Err(errors::internal(&error, fragment_shell(user.locale())).into());
    }
    Ok(screen::moved(visit.record()))
}

/// `POST {PREFIX}/{id}/results`: opens step 8 once the apply ended.
///
/// # Errors
///
/// Answers the refusal of the run and 409 while the apply runs.
// cancel-safe: reads, then one record write.
pub(crate) async fn results<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
) -> Result<Response, Answer>
where
    F: Flow,
{
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::APPLY {
        return Ok(screen::moved(visit.record()));
    }
    let interrupted = visit.session().live().is_none();
    if !visit.record_mut().show_results(interrupted) {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    visit
        .save()
        .await
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    Ok(screen::moved(visit.record()))
}
