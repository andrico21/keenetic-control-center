//! Step 4's submits: the Apply boxes of the shown page save as they change (204), and
//! Continue moves on to the inputs.

use alloc::{collections::BTreeSet, sync::Arc};

use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use serde_json::json;

use super::{access::Visit, fates::Fate, plan::Basis, screen, steps::Step};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    migrate_wizard::{access::Services, service::Wizards},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `POST /ui/presets/runs/{run}/review`: saves the shown page's choices.
///
/// # Errors
///
/// Answers the refusal of the run, and 409 when it is not at its review.
// cancel-safe: see `decide`.
pub(super) async fn save(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Review {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    decide(&mut visit, &form).await?;
    drop(visit);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /ui/presets/runs/{run}/review/continue`: saves the shown page's choices and
/// moves on to the inputs.
///
/// # Errors
///
/// Answers the refusal of the run.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn proceed(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Review {
        return Ok(screen::moved(visit.record()));
    }
    decide(&mut visit, &form).await?;
    visit.record_mut().review_done();
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(user.locale())).into());
    }
    let record = visit.record();
    Audit::on_router(
        "web.preset_review",
        record.target().unwrap_or_default(),
        id.clone(),
    )
    .with_params(json!({ "excluded": record.excluded().len() }))
    .append(&state, &user, "saved")
    .await;
    Ok(screen::moved(visit.record()))
}

/// Records the Apply boxes `form` sends for its shown settings.
///
/// # Errors
///
/// Answers 422 when the plan cannot be made, 500 when the record cannot be written.
// cancel-safe: reads, then one record write.
async fn decide(visit: &mut Visit<'_>, form: &[(String, String)]) -> Result<(), Answer> {
    let locale = visit.services().user().locale();
    let unprocessable = || Answer::from(StatusCode::UNPROCESSABLE_ENTITY.into_response());
    let basis = Basis::of(visit).await.map_err(|_problem| unprocessable())?;
    let plan = basis
        .plan(visit.record())
        .map_err(|_error| unprocessable())?;
    let indices = |name: &str| {
        form.iter()
            .filter(|(field, _)| field == name)
            .filter_map(|(_, value)| value.parse::<usize>().ok())
            .collect::<BTreeSet<_>>()
    };
    let included = indices("include");
    for index in indices("shown") {
        let choosable = plan
            .items
            .iter()
            .find(|item| item.index == index)
            .is_some_and(|item| Fate::of(item, false).choosable());
        if choosable {
            visit.record_mut().include(index, included.contains(&index));
        }
    }
    visit
        .save()
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))
}
