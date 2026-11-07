//! Resuming a migration at its current step, and Back.
//!
//! `GET /ui/migrate/{id}` shows the current step, whatever the browser did before (a
//! reload, another tab, a restart of kcc); Back shows an earlier step while choices can
//! still change.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use super::{
    access::{Services, Visit},
    inputs::{self, Shown},
    kinds::Step,
    mapping, preview, report, results,
    review::{self, View},
    running, screen,
    service::Wizards,
    source, target,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page_kit::{
        context::{Caller, Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `GET /ui/migrate/{id}`: the migration at its current step.
#[expect(
    clippy::significant_drop_tightening,
    reason = "every step's panel reads the record, which lives in the visit holding the turn"
)]
pub(super) async fn page(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(view): Query<View>,
    Extension(wizards): Extension<Arc<Wizards>>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Migration, None)
        .await;
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let visit = match Visit::open(services, &wizards, &id).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let record = visit.record();
    match record.step() {
        Step::Source => {
            let panel = source::Panel::new(services, record.id(), record.source()).await;
            screen::page(shell, record, &panel)
        }
        Step::Target => screen::page(shell, record, &target::Panel::new(&visit).await),
        Step::Mapping => screen::page(shell, record, &mapping::Panel::new(&visit).await),
        Step::Review => screen::page(shell, record, &review::Panel::new(&visit, &view).await),
        Step::Inputs => {
            let panel = inputs::Panel::new(&visit, Shown::default()).await;
            screen::page(shell, record, &panel)
        }
        Step::Preview => screen::page(shell, record, &preview::Panel::new(&visit).await),
        Step::Apply => screen::page(shell, record, &running::Panel::new(&visit)),
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

/// `POST /ui/migrate/{id}/back`: shows an earlier step again, when choices can still
/// change; the choices stay until that step is submitted differently.
///
/// # Errors
///
/// Answers the refusal of the migration.
pub(super) async fn back(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(back): Form<Back>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record_mut().go_back(back.step)
        && let Err(error) = visit.save()
    {
        return Err(errors::internal(&error, fragment_shell(user.locale())).into());
    }
    Ok(screen::moved(visit.record()))
}
