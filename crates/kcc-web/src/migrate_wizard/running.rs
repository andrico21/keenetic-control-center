//! Step 7: the apply, followed live, with Stop while it runs; once it ended, Review the
//! result opens step 8.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_i18n::keys;

use super::{
    access::{Services, Visit},
    kinds::Step,
    screen,
    service::Wizards,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        outcome::Toast,
        respond::Answer,
    },
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_apply.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// Whether the job still runs: Stop shows.
    running: bool,
}

localized!(Panel);

impl Panel {
    /// The panel of `visit`.
    pub(super) fn new(visit: &Visit<'_>) -> Self {
        let running = visit
            .session()
            .live()
            .is_some_and(|live| live.watch().borrow().running());
        Self {
            shell: fragment_shell(visit.services().user().locale()),
            id: visit.record().id().to_owned(),
            running,
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

/// `POST /ui/migrate/{id}/stop`: cancels the apply's job; the engine stops before its
/// next setting and the result offers the rollback.
///
/// # Errors
///
/// Answers the refusal of the migration and 409 when no apply runs.
pub(super) async fn stop(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &wizards, &id)
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
    Audit::on_router("web.migrate_stop", &target, id)
        .append(&state, &user, outcome)
        .await;
    Ok(errors::render(&Answered {
        shell: fragment_shell(locale),
        toast,
    }))
}

/// `POST /ui/migrate/{id}/results`: opens step 8 once the apply ended.
///
/// # Errors
///
/// Answers the refusal of the migration and 409 while the apply runs.
pub(super) async fn results(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let session = visit.session();
    if visit.record().step() != Step::Apply {
        return Ok(screen::moved(visit.record()));
    }
    let interrupted = session.live().is_none();
    if !visit.record_mut().show_results(interrupted) {
        return Err(StatusCode::CONFLICT.into_response().into());
    }
    visit
        .save()
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    Ok(screen::moved(visit.record()))
}
