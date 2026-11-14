//! Step 8's choices: Commit, Roll back (the router name typed, `Destructive`), Review
//! the plan again after components were installed, Back to the preview after an apply
//! that changed nothing, and Finish.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::audit::Attempt;
use kcc_i18n::{bundle::tr, keys};
use kcc_migrate::apply::{Applier, ApplyError};

use super::{
    access::Visit,
    kinds::{Finish, Step},
    preview::commit_permissions,
    record::Record,
    results::{Panel, ROLLBACK},
};
use crate::{
    WebState,
    authz::CurrentUser,
    brackets,
    errors::{self, Kind},
    page_kit::{
        audit::Record as Audit,
        confirm::{Ask, Confirmation, Dialog, Resubmit, Typed, Words},
        context::{Refusal, fragment_shell},
        gate::allowed,
        respond::Answer,
    },
    wizard::{flow::Flow as _, run::failure_text, screen, service::Wizards, services::Services},
};

/// The choice a finishing request makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    /// Save the verified changes.
    Commit,
    /// Restore the saved configuration.
    Rollback,
}

/// `POST /ui/migrate/{id}/commit`: saves the verified changes.
///
/// # Errors
///
/// Answers the refusal of the migration, the audited 403, and the results with the
/// reason (422) when the commit fails.
pub(super) async fn commit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    finish(&state, &wizards, &user, (&id, Choice::Commit)).await
}

/// `POST /ui/migrate/{id}/rollback`: asks for the router name, then restores the
/// configuration the router saved before the migration.
///
/// # Errors
///
/// Answers the refusal of the migration, the audited 403, the confirmation, and the
/// results with the reason (422) when the rollback fails.
pub(super) async fn rollback(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let target = visit.record().target().unwrap_or_default().to_owned();
    drop(visit);
    let locale = user.locale();
    if !form.confirmed() || form.name() != Some(target.as_str()) {
        let mut args = FluentArgs::new();
        args.set("router", target.clone());
        let words = Words::new(
            tr(locale, keys::WEB_MIGRATE_ROLLBACK_TITLE, Some(&args)),
            tr(locale, keys::WEB_MIGRATE_ROLLBACK_TEXT, Some(&args)),
            tr(locale, keys::MIGRATE_ROLLBACK, None),
        );
        let error = if form.confirmed() {
            tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
        } else {
            String::new()
        };
        let action = format!("/ui/migrate/{id}/rollback");
        let asked = Ask::Typed(Typed::router(locale).with_error(error));
        let resubmit = Resubmit::new(action, "#wizard-step");
        return Ok(Dialog::new(locale, words, resubmit).asking(asked).show());
    }
    finish(&state, &wizards, &user, (&id, Choice::Rollback)).await
}

/// Commits or rolls back migration `id` as `choice`.
///
/// # Errors
///
/// As [`commit`] and [`rollback`].
// NOT cancel-safe: a commit or rollback sent to the router may finish without its record.
async fn finish(
    state: &WebState,
    wizards: &Arc<Wizards<Record>>,
    user: &CurrentUser,
    (id, choice): (&str, Choice),
) -> Result<Response, Answer> {
    let services = Services::of(state, user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, wizards, id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Results {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let session = visit.session();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let (action, needed, finished) = match choice {
        Choice::Commit => (
            "web.migrate_commit",
            commit_permissions(),
            Finish::Committed,
        ),
        Choice::Rollback => (
            "web.migrate_rollback",
            ROLLBACK.to_vec(),
            Finish::RolledBack,
        ),
    };
    let audit = Audit::on_router(action, &target, id.to_owned());
    if !allowed(user, &target, &needed) {
        audit.append(state, user, "forbidden").await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    }
    let Some(live) = session.live() else {
        return Err(StatusCode::CONFLICT.into_response().into());
    };
    let mut slot = live.applier().await;
    let Some(applier) = slot.as_mut() else {
        return Err(StatusCode::CONFLICT.into_response().into());
    };
    if !brackets::hold() {
        tracing::warn!("finish refused: its request has no server owner");
        return Err(errors::response(Kind::Internal, fragment_shell(locale)).into());
    }
    let result = match choice {
        Choice::Commit => applier.commit().await,
        Choice::Rollback => applier.rollback().await,
    };
    if let Err(error) = result {
        drop(slot);
        let failed = Attempt::Failed {
            error: "router",
            fail_safe_armed: error.recovery_armed(),
        };
        audit.append_attempt(state, user, failed).await;
        if error == ApplyError::RollbackRestarting {
            end(state, wizards, &mut visit, (id, Finish::RollbackRestarting))?;
            return Ok(screen::moved(visit.record()));
        }
        let reason = tr(locale, failure_text(error), None);
        let panel = Panel::new(&visit).await.refusing(reason);
        return Err(screen::refused(&panel).into());
    }
    let done: Option<Applier> = slot.take();
    drop(slot);
    drop(done);
    end(state, wizards, &mut visit, (id, finished))?;
    audit.append(state, user, "done").await;
    Ok(screen::moved(visit.record()))
}

/// Ends migration `id` as `how`: drops its applier, frees the target and saves the record.
///
/// # Errors
///
/// Answers 500 when the record cannot be saved.
fn end(
    state: &WebState,
    wizards: &Wizards<Record>,
    visit: &mut Visit<'_>,
    (id, how): (&str, Finish),
) -> Result<(), Answer> {
    let target = visit.record().target().unwrap_or_default().to_owned();
    visit.session().set_live(None);
    wizards.release(&target, id);
    visit.record_mut().finish(how, state.unix_seconds());
    visit.save().map_err(|error| {
        Answer::from(errors::internal(
            &error,
            fragment_shell(visit.services().user().locale()),
        ))
    })
}

/// `POST /ui/migrate/{id}/{replan,retry,close}`: plans again from the maps (after
/// components were installed), returns to the preview (nothing changed), or finishes an
/// apply with no changes to keep.
///
/// # Errors
///
/// Answers the refusal of the migration, and 409 while changes wait for commit or
/// rollback.
pub(super) async fn settle(
    State(state): State<WebState>,
    Path((id, way)): Path<(String, String)>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Results {
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
    match way.as_str() {
        "replan" => {
            session.forget();
            visit.record_mut().plan_again(Step::Mapping);
        }
        "retry" => visit.record_mut().plan_again(Step::Preview),
        "close" => {
            let how = if pending == Some(true) {
                Finish::RolledBackByRouter
            } else {
                Finish::Closed
            };
            visit.record_mut().finish(how, state.unix_seconds());
        }
        _ => return Err(StatusCode::NOT_FOUND.into_response().into()),
    }
    session.set_live(None);
    wizards.release(&target, &id);
    visit
        .save()
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    Ok(screen::moved(visit.record()))
}
