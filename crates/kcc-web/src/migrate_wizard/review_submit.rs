//! Step 4's submits: the choices of the shown page save as they change (204), and
//! Continue moves on once every setting whose value differs from the router's has its
//! choice.

use alloc::{collections::BTreeSet, sync::Arc};

use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys};
use serde_json::json;

use super::{
    access::{Migration as _, Visit},
    kinds::Step,
    plan::Classified,
    record::Record,
    review::{Panel, View},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        request::last,
        respond::{self, Answer},
    },
    wizard::{flow::Flow as _, screen, service::Wizards, services::Services},
};

/// `POST /ui/migrate/{id}/review`: saves the shown page's choices.
///
/// # Errors
///
/// Answers the refusal of the migration, and 409 when it is not at its review.
pub(super) async fn save(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Review {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    let _: usize = decide(&mut visit, &form).await?;
    drop(visit);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /ui/migrate/{id}/review/continue`: saves the shown page's choices and moves on
/// to the inputs when no conflict waits for a choice.
///
/// # Errors
///
/// Answers the refusal of the migration, and the review with the reason (422).
pub(super) async fn proceed(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Review {
        return Ok(screen::moved(visit.record()));
    }
    let unresolved = decide(&mut visit, &form).await?;
    let locale = user.locale();
    if unresolved > 0 {
        let mut args = FluentArgs::new();
        args.set("count", u32::try_from(unresolved).unwrap_or(u32::MAX));
        let error = tr(locale, keys::WEB_MIGRATE_REVIEW_UNRESOLVED, Some(&args));
        let view = View::default();
        let panel = Panel::new(&visit, &view).await.refusing(error);
        return Err(respond::unprocessable(&panel).into());
    }
    visit.record_mut().review_done();
    if let Err(error) = visit.save().await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let record = visit.record();
    Audit::on_router(
        "web.migrate_review",
        record.target().unwrap_or_default(),
        id.clone(),
    )
    .with_params(json!({
        "excluded": record.excluded().len(),
        "overwrite": record.overwrite().len(),
    }))
    .append(&state, &user, "saved")
    .await;
    Ok(screen::moved(visit.record()))
}

/// Records the choices `form` sends for its shown settings and returns how many
/// conflicts still wait for a choice.
///
/// # Errors
///
/// Answers 422 when the settings cannot be classified, 500 when the record cannot be
/// written.
// cancel-safe: reads, then one record write.
async fn decide(visit: &mut Visit<'_>, form: &[(String, String)]) -> Result<usize, Answer> {
    let locale = visit.services().user().locale();
    let analysis = visit
        .analysis()
        .await
        .map_err(|_problem| Answer::from(StatusCode::UNPROCESSABLE_ENTITY.into_response()))?;
    let passwords = visit
        .passwords()
        .await
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))?;
    let classified = Classified::new(&analysis, visit.record(), &passwords)
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))?;
    let count = classified.items().len();
    let indices = |name: &str| {
        form.iter()
            .filter(|(field, _)| field == name)
            .filter_map(|(_, value)| value.parse::<usize>().ok())
            .filter(|index| *index < count)
            .collect::<BTreeSet<_>>()
    };
    let included = indices("include");
    for index in indices("shown") {
        let excludable = classified
            .items()
            .get(index)
            .is_some_and(|item| item.output.is_some() || item.needed_input.is_some());
        let field = format!("resolve-{index}");
        let chosen = last(form, &field);
        match (classified.conflicts(index), chosen, excludable) {
            (true, Some("source"), _) => visit.record_mut().decide(index, false, true),
            (true, Some("router"), _) => visit.record_mut().decide(index, true, false),
            (true, _, _) => visit.record_mut().decide(index, false, false),
            (false, _, true) => {
                visit
                    .record_mut()
                    .decide(index, !included.contains(&index), false);
            }
            (false, _, false) => {}
        }
    }
    visit
        .save()
        .await
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))?;
    Ok(classified.unresolved(visit.record()))
}
