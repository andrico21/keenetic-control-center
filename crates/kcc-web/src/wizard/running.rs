//! Step 7: the apply, followed live over the event stream, with Stop while it runs.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{flow::Flow, service::Wizards, services::Services, visit::Visit};
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
#[template(path = "partials/wizard_apply.html")]
pub(crate) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// The step's title.
    title: String,
    /// What the step does.
    text: String,
    /// Where the wizard's run pages are.
    prefix: &'static str,
    /// Run id.
    id: String,
    /// Whether the job still runs: Stop shows.
    running: bool,
}

localized!(Panel);

impl Panel {
    /// The panel of `visit`, titled and explained by the keys `(title, text)`.
    pub(crate) fn new<F>(visit: &Visit<'_, F>, (title, text): (MessageKey, MessageKey)) -> Self
    where
        F: Flow,
    {
        let locale = visit.services().user().locale();
        let running = visit
            .session()
            .live()
            .is_some_and(|live| live.watch().borrow().running());
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, title, None),
            text: tr(locale, text, None),
            prefix: F::PREFIX,
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

/// `POST {PREFIX}/{id}/stop`: cancels the apply's job; the engine stops before its
/// next setting and the result offers the rollback.
///
/// # Errors
///
/// Answers the refusal of the run and 409 when no apply runs.
// NOT cancel-safe: the job may stop before its audit append.
pub(crate) async fn stop<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
) -> Result<Response, Answer>
where
    F: Flow,
{
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
    Audit::on_router(F::STOP, &target, id)
        .append(&state, &user, outcome)
        .await;
    Ok(errors::render(&Answered {
        shell: fragment_shell(locale),
        toast,
    }))
}
