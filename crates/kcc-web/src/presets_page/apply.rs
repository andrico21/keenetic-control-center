//! Steps 6 to 8: Apply, Stop and Review the result.
//!
//! Apply asks first, then reserves the target (one apply per router at a time among the
//! presets' runs) and starts the apply; step 7 follows it live with Stop, and Review the
//! result opens step 8 once it ended.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use kcc_migrate::apply::ApplyOptions;
use serde_json::json;

use super::{
    access::Visit,
    launch::{Failure, launch},
    preview::{Panel, apply_permissions},
    screen,
    steps::Step,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    migrate_wizard::{
        access::Services,
        confirm::{Confirm, Dialog, Words, refused},
        service::Wizards,
    },
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        outcome::Toast,
        respond::Answer,
    },
};

/// Step 7's panel: the live apply.
#[derive(Template)]
#[template(path = "partials/presets_apply.html")]
pub(super) struct Running {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// Whether the job still runs: Stop shows.
    stoppable: bool,
}

localized!(Running);

impl Running {
    /// The panel of `visit`.
    pub(super) fn new(visit: &Visit<'_>) -> Self {
        let stoppable = visit
            .session()
            .live()
            .is_some_and(|live| live.watch().borrow().running());
        Self {
            shell: fragment_shell(visit.services().user().locale()),
            id: visit.record().id().to_owned(),
            stoppable,
        }
    }
}

/// A toast answering Stop.
#[derive(Template)]
#[template(
    ext = "html",
    source = "{%- import \"components.html\" as ui -%}{{ ui::toast(toast.tone(), toast.message()) }}"
)]
struct Answered {
    /// Locale carrier.
    shell: Shell,
    /// The toast.
    toast: Toast,
}

localized!(Answered);

/// `POST /ui/presets/runs/{run}/apply`: asks first, then starts the apply.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403 without the permissions the apply
/// needs, and the preview with the reason (422) when it cannot start.
// NOT cancel-safe: see `launch`.
pub(super) async fn apply(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Confirm>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Preview {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let audit = Audit::on_router("web.preset_apply", &target, id.clone());
    let missing = errors::refusal::missing(&user, &target, &apply_permissions());
    if !missing.is_empty() {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::refusal::refused(locale, &missing, "#wizard-step").into());
    }
    let Some(jobs) = state.advanced().jobs().cloned() else {
        return Err(refusal(&visit, &state, keys::WEB_MIGRATE_APPLY_NO_JOBS).await);
    };
    if !form.confirmed() {
        let mut args = FluentArgs::new();
        args.set("router", target.clone());
        let minutes = ApplyOptions::default().safety_seconds.div_ceil(60);
        args.set("minutes", u32::try_from(minutes).unwrap_or(u32::MAX));
        let words = Words::new(
            tr(locale, keys::WEB_PRESETS_APPLY_CONFIRM_TITLE, Some(&args)),
            tr(locale, keys::WEB_PRESETS_APPLY_CONFIRM_TEXT, Some(&args)),
            tr(locale, keys::WEB_PRESETS_APPLY_BUTTON, None),
        );
        return Ok(Dialog::new(locale, words, format!("/ui/presets/runs/{id}/apply")).show());
    }
    if !runs.claim(&target, &id) {
        audit.append(&state, &user, "busy").await;
        return Err(refusal(&visit, &state, keys::WEB_PRESETS_APPLY_BUSY).await);
    }
    match launch(&mut visit, &state, &jobs, &runs).await {
        Ok((job, commands)) => {
            audit
                .with_params(json!({ "job": job, "commands": commands }))
                .append(&state, &user, "started")
                .await;
            Ok(screen::moved(visit.record()))
        }
        Err(failure) => {
            runs.release(&target, &id);
            match failure {
                Failure::Refused(key, outcome) => {
                    audit.append(&state, &user, outcome).await;
                    Err(refusal(&visit, &state, key).await)
                }
                Failure::Broken(error) => {
                    Err(errors::internal(&error, fragment_shell(locale)).into())
                }
            }
        }
    }
}

/// The preview again with `key` as its reason, as 422 in the step.
// cancel-safe: reads only.
async fn refusal(visit: &Visit<'_>, state: &WebState, key: MessageKey) -> Answer {
    let locale = visit.services().user().locale();
    let panel = Panel::new(visit, state)
        .await
        .refusing(tr(locale, key, None));
    refused(&panel).into()
}

/// `POST /ui/presets/runs/{run}/stop`: cancels the apply's job; the engine stops before
/// its next setting and the result offers the rollback.
///
/// # Errors
///
/// Answers the refusal of the run and 409 when no apply runs.
// NOT cancel-safe: the job may stop before its audit append.
pub(super) async fn stop(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    let (Some(run), Some(jobs)) = (visit.record().run(), state.advanced().jobs()) else {
        return Err(StatusCode::CONFLICT.into_response().into());
    };
    let locale = user.locale();
    let cancelled = jobs.cancel(run.job()).await;
    let target = visit.record().target().unwrap_or_default().to_owned();
    drop(visit);
    let (toast, outcome) = match cancelled {
        Ok(()) => (
            Toast::success(locale, keys::WEB_MIGRATE_STOPPING),
            "stopping",
        ),
        Err(_ended) => (
            Toast::warning(locale, keys::WEB_EXPLORER_JOB_NOT_RUNNING),
            "not_running",
        ),
    };
    Audit::on_router("web.preset_stop", &target, id)
        .append(&state, &user, outcome)
        .await;
    Ok(errors::render(&Answered {
        shell: fragment_shell(locale),
        toast,
    }))
}

/// `POST /ui/presets/runs/{run}/results`: opens step 8 once the apply ended.
///
/// # Errors
///
/// Answers the refusal of the run and 409 while the apply runs.
// cancel-safe: reads, then one record write.
pub(super) async fn results(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Apply {
        return Ok(screen::moved(visit.record()));
    }
    let interrupted = visit.session().live().is_none();
    if !visit.record_mut().show_results(interrupted) {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    visit
        .save()
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    Ok(screen::moved(visit.record()))
}
