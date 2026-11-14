//! Step 8's choices that the router carries out.
//!
//! Keep the verified changes as the wizard offers (a migration commits; a preset run
//! keeps them unsaved or saves them) or roll them back (the router name typed; it needs
//! `Destructive`).
//!
//! The routes differ per wizard and stay as they are: a migration posts `commit` and
//! `rollback` to their own routes ([`commit`], [`rollback`]; the rollback asks for the
//! name before the step is checked), a preset run posts every choice to one route
//! ([`choose`]; an unknown choice is 404 before the run opens). Every choice runs through
//! the same checks, audit, fail-safe bracket and end.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::audit::Attempt;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::apply::{Applier, ApplyError};

use super::{
    finishing::{Choice, Finishing, Settle},
    results::Panel,
    screen,
    service::Wizards,
    services::Services,
    settle,
    visit::Visit,
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
};

/// `POST {PREFIX}/{id}/commit`: saves the verified changes.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403, and the results with the reason
/// (422) when the commit fails.
// NOT cancel-safe: a commit sent to the router may finish without its record.
pub(crate) async fn commit<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::RESULTS {
        return Ok(screen::moved(visit.record()));
    }
    finish(&state, &wizards, &user, (&id, visit, Choice::Commit)).await
}

/// `POST {PREFIX}/{id}/rollback`: asks for the router name, then restores the
/// configuration the router saved before the apply.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403, the confirmation, and the results
/// with the reason (422) when the rollback fails.
// NOT cancel-safe: a rollback sent to the router may finish without its record.
pub(crate) async fn rollback<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let opened = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let target = opened.record().target().unwrap_or_default().to_owned();
    drop(opened);
    if let Some(dialog) = ask::<F>(&form, (&id, &target), user.locale()) {
        return Ok(dialog);
    }
    let visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::RESULTS {
        return Ok(screen::moved(visit.record()));
    }
    finish(&state, &wizards, &user, (&id, visit, Choice::Rollback)).await
}

/// `POST {PREFIX}/{id}/{way}`: one of step 8's choices, the wizard's keep buttons,
/// `rollback`, `retry` or `close`.
///
/// # Errors
///
/// Answers the refusal of the run, 404 for another way, the audited 403, the rollback's
/// confirmation, 409 while changes wait for a choice that cannot be made now, and the
/// results with the reason (422) when the router refuses.
// NOT cancel-safe: the router may finish before the record and the audit say so.
pub(crate) async fn choose<F>(
    State(state): State<WebState>,
    Path((id, way)): Path<(String, String)>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let choice = match way.as_str() {
        "rollback" => Choice::Rollback,
        "retry" => {
            return settle::settle(&state, &wizards, &user, (&id, Some(Settle::Retry))).await;
        }
        "close" => {
            return settle::settle(&state, &wizards, &user, (&id, Some(Settle::Close))).await;
        }
        other => match F::KEEPING.iter().find(|&&(_, known, _, _)| known == other) {
            Some(&(choice, ..)) => choice,
            None => return Err(StatusCode::NOT_FOUND.into_response().into()),
        },
    };
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::RESULTS {
        return Ok(screen::moved(visit.record()));
    }
    let target = visit.record().target().unwrap_or_default();
    if choice == Choice::Rollback
        && let Some(dialog) = ask::<F>(&form, (&id, target), user.locale())
    {
        return Ok(dialog);
    }
    finish(&state, &wizards, &user, (&id, visit, choice)).await
}

/// The rollback's confirmation for run `id` on `target`, unless `form` typed its name.
fn ask<F>(form: &Confirmation, (id, target): (&str, &str), locale: Locale) -> Option<Response>
where
    F: Finishing,
{
    if form.confirmed() && form.name() == Some(target) {
        return None;
    }
    let mut args = FluentArgs::new();
    args.set("router", target.to_owned());
    let (title, text) = F::ROLLBACK_WORDS;
    let words = Words::new(
        tr(locale, title, Some(&args)),
        tr(locale, text, Some(&args)),
        tr(locale, keys::MIGRATE_ROLLBACK, None),
    );
    let error = if form.confirmed() {
        tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
    } else {
        String::new()
    };
    let action = format!("{}/{id}/rollback", F::PREFIX);
    let asked = Ask::Typed(Typed::router(locale).with_error(error));
    let resubmit = Resubmit::new(action, "#wizard-step");
    Some(Dialog::new(locale, words, resubmit).asking(asked).show())
}

/// Makes `choice` on run `id`, which `visit` opened at step 8.
///
/// # Errors
///
/// As [`choose`].
// NOT cancel-safe: a choice sent to the router may finish without its record.
async fn finish<F>(
    state: &WebState,
    wizards: &Wizards<F>,
    user: &CurrentUser,
    (id, mut visit, choice): (&str, Visit<'_, F>, Choice),
) -> Result<Response, Answer>
where
    F: Finishing,
{
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let Some((action, needed, finished)) = F::choice(choice) else {
        return Err(StatusCode::NOT_FOUND.into_response().into());
    };
    let audit = Audit::on_router(action, &target, id.to_owned());
    if !allowed(user, &target, &needed) {
        audit.append(state, user, "forbidden").await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    }
    let session = visit.session();
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
        Choice::Keep => applier.keep_unsaved().await,
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
            end(state, wizards, &mut visit, (id, F::ROLLBACK_RESTARTING))?;
            return Ok(screen::moved(visit.record()));
        }
        let reason = tr(locale, F::failure_text(error), None);
        let panel = Panel::new(&visit).await.refusing(reason);
        return Err(screen::refused(&panel).into());
    }
    let done: Option<Applier> = slot.take();
    drop(slot);
    drop(done);
    end(state, wizards, &mut visit, (id, finished))?;
    let audited = match F::audit_params(finished) {
        Some(params) => audit.with_params(params),
        None => audit,
    };
    audited.append(state, user, "done").await;
    Ok(screen::moved(visit.record()))
}

/// Ends run `id`, which `visit` opened, as `how`: drops its applier, frees the target, saves the
/// record and deletes what the run sealed for its apply.
///
/// # Errors
///
/// Answers 500 when the record cannot be saved.
fn end<F>(
    state: &WebState,
    wizards: &Wizards<F>,
    visit: &mut Visit<'_, F>,
    (id, how): (&str, F::Finish),
) -> Result<(), Answer>
where
    F: Finishing,
{
    let target = visit.record().target().unwrap_or_default().to_owned();
    visit.session().set_live(None);
    wizards.release(&target, id);
    visit.record_mut().finish(how, state.unix_seconds());
    let services = visit.services();
    visit.save().map_err(|error| {
        Answer::from(errors::internal(
            &error,
            fragment_shell(services.user().locale()),
        ))
    })?;
    F::discard(services, id);
    Ok(())
}
