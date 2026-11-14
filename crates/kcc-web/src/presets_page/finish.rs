//! Step 8's choices: keep unsaved, save, roll back, back to the preview, finish.
//!
//! `POST /ui/presets/runs/{run}/{keep,save,rollback}` finish the applied settings (Roll
//! back asks for the router name and needs `Destructive`); `{retry,close}` return to the
//! preview or finish an apply that changed nothing. Finishing deletes what the run
//! sealed: the copied settings and the typed passwords.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{audit::Attempt, permissions::Permission};
use kcc_i18n::{bundle::tr, keys};
use kcc_migrate::apply::{Applier, ApplyError};
use serde_json::json;

use super::{
    access::Visit,
    events::failure_text,
    record::Record,
    results::{KEEP, Panel, ROLLBACK, SAVE},
    saved,
    steps::{Finish, Step},
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
    wizard::{flow::Flow as _, screen, screen::refused, service::Wizards, services::Services},
};

/// The final choice of applied settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    /// Disarm the timer and save nothing.
    Keep,
    /// Save the verified settings.
    Save,
    /// Restore the saved configuration.
    Rollback,
}

impl Choice {
    /// The audit action, the permissions it needs and how the run then finished.
    const fn facts(self) -> (&'static str, &'static [Permission], Finish) {
        match self {
            Self::Keep => ("web.preset_keep", &KEEP, Finish::KeptUnsaved),
            Self::Save => ("web.preset_save", &SAVE, Finish::Saved),
            Self::Rollback => ("web.preset_rollback", &ROLLBACK, Finish::RolledBack),
        }
    }
}

/// `POST /ui/presets/runs/{run}/{way}`: one of step 8's choices.
///
/// # Errors
///
/// Answers the refusal of the run, 404 for another way, the audited 403, the rollback's
/// confirmation, 409 while settings wait for a choice that cannot be made now, and the
/// results with the reason (422) when the router refuses.
// NOT cancel-safe: the router may finish before the record and the audit say so.
pub(super) async fn finish(
    State(state): State<WebState>,
    Path((id, way)): Path<(String, String)>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer> {
    let choice = match way.as_str() {
        "keep" => Choice::Keep,
        "save" => Choice::Save,
        "rollback" => Choice::Rollback,
        "retry" | "close" => return settle(&state, &runs, &user, (&id, &way)).await,
        _ => return Err(StatusCode::NOT_FOUND.into_response().into()),
    };
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Results {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let confirmed = form.confirmed() && form.name() == Some(target.as_str());
    if choice == Choice::Rollback && !confirmed {
        let mut args = FluentArgs::new();
        args.set("router", target.clone());
        let words = Words::new(
            tr(locale, keys::WEB_PRESETS_ROLLBACK_TITLE, Some(&args)),
            tr(locale, keys::WEB_PRESETS_ROLLBACK_TEXT, Some(&args)),
            tr(locale, keys::MIGRATE_ROLLBACK, None),
        );
        let error = if form.confirmed() {
            tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
        } else {
            String::new()
        };
        let action = format!("/ui/presets/runs/{id}/rollback");
        let asked = Ask::Typed(Typed::router(locale).with_error(error));
        let resubmit = Resubmit::new(action, "#wizard-step");
        return Ok(Dialog::new(locale, words, resubmit).asking(asked).show());
    }
    let (action, needed, finished) = choice.facts();
    let audit = Audit::on_router(action, &target, id.clone());
    if !allowed(&user, &target, needed) {
        audit.append(&state, &user, "forbidden").await;
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
        Choice::Save => applier.commit().await,
        Choice::Rollback => applier.rollback().await,
    };
    if let Err(error) = result {
        drop(slot);
        let failed = Attempt::Failed {
            error: "router",
            fail_safe_armed: error.recovery_armed(),
        };
        audit.append_attempt(&state, &user, failed).await;
        if error == ApplyError::RollbackRestarting {
            end(&state, &runs, &mut visit, (&id, Finish::RollbackRestarting))?;
            return Ok(screen::moved(visit.record()));
        }
        let reason = tr(locale, failure_text(error), None);
        let panel = Panel::new(&visit).await.refusing(reason);
        return Err(refused(&panel).into());
    }
    let done: Option<Applier> = slot.take();
    drop(slot);
    drop(done);
    end(&state, &runs, &mut visit, (&id, finished))?;
    audit
        .with_params(json!({ "finish": finished.slug() }))
        .append(&state, &user, "done")
        .await;
    Ok(screen::moved(visit.record()))
}

/// Ends run `id` as `how`: drops its applier, frees the target, saves the record and
/// deletes what the run sealed.
///
/// # Errors
///
/// Answers 500 when the record cannot be saved.
fn end(
    state: &WebState,
    runs: &Wizards<Record>,
    visit: &mut Visit<'_>,
    (id, how): (&str, Finish),
) -> Result<(), Answer> {
    let target = visit.record().target().unwrap_or_default().to_owned();
    visit.session().set_live(None);
    runs.release(&target, id);
    visit.record_mut().finish(how, state.unix_seconds());
    let services = visit.services();
    visit.save().map_err(|error| {
        Answer::from(errors::internal(
            &error,
            fragment_shell(services.user().locale()),
        ))
    })?;
    saved::discard(services, id);
    Ok(())
}

/// Back to the preview after an apply that changed nothing (`retry`), or Finish
/// (`close`) once nothing waits for a choice.
///
/// # Errors
///
/// Answers the refusal of the run, and 409 while settings wait for a choice.
// cancel-safe: every change comes after the last await.
async fn settle(
    state: &WebState,
    runs: &Arc<Wizards<Record>>,
    user: &CurrentUser,
    (id, way): (&str, &str),
) -> Result<Response, Answer> {
    let services = Services::of(state, user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, runs, id)
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
    let closing = way == "close";
    if closing {
        let how = if pending == Some(true) {
            Finish::RolledBackByRouter
        } else {
            Finish::Closed
        };
        visit.record_mut().finish(how, state.unix_seconds());
    } else {
        visit.record_mut().plan_again();
    }
    session.set_live(None);
    runs.release(&target, id);
    visit
        .save()
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    if closing {
        saved::discard(services, id);
    }
    Ok(screen::moved(visit.record()))
}
