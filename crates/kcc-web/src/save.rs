//! Save, the primary action of the dashboard's unsaved-changes banner.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind},
    workflow::WorkflowError,
};
use kcc_i18n::{bundle::tr, keys};
use tokio::time::timeout;

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell, Theme},
};

/// How long Save waits for the router before answering that it is still saving; the
/// save itself continues and is audited either way.
const SAVE_WAIT: Duration = Duration::from_secs(25);

/// The toast that answers Save.
#[derive(Template)]
#[template(path = "partials/save_result.html")]
struct SaveResult {
    /// Locale carrier.
    shell: Shell,
    /// Toast tone: success, info or error.
    tone: &'static str,
    /// The localized outcome.
    message: String,
    /// Whether the save completed, which hides the banner at once.
    saved: bool,
}

localized!(SaveResult);

/// `POST /ui/r/{router}/save`: saves the running configuration through the change
/// workflow and answers with a toast.
// NOT cancel-safe: the save command may persist the configuration before the future is dropped.
pub(crate) async fn save(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Response {
    let shell = Shell::new(user.locale(), Theme::System);
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let workflow = Arc::clone(fleet.workflow());
    let actor = Actor::new(ActorKind::Web, user.username().to_owned());
    let role = user.role().clone();
    let task = tokio::spawn(async move {
        let mut changes = workflow.begin(&router, actor, &role, false).await?;
        changes.save().await
    });
    let locale = user.locale();
    let (tone, message, saved) = match timeout(SAVE_WAIT, task).await {
        Ok(Ok(Ok(()))) => ("success", tr(locale, keys::WEB_SAVE_DONE, None), true),
        Ok(Ok(Err(WorkflowError::RouterBusy { actor: holder }))) => {
            let mut args = FluentArgs::new();
            args.set("user", holder);
            ("error", tr(locale, keys::WEB_SAVE_BUSY, Some(&args)), false)
        }
        Ok(Ok(Err(WorkflowError::Conflict { agent: _ }))) => {
            ("error", tr(locale, keys::WEB_SAVE_CONFLICT, None), false)
        }
        Ok(Ok(Err(error))) => {
            tracing::error!(%error, "web save failed");
            ("error", tr(locale, keys::WEB_SAVE_FAILED, None), false)
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "web save task failed");
            ("error", tr(locale, keys::WEB_SAVE_FAILED, None), false)
        }
        Err(_elapsed) => ("info", tr(locale, keys::WEB_SAVE_PENDING, None), false),
    };
    errors::render(&SaveResult {
        shell,
        tone,
        message,
        saved,
    })
}
