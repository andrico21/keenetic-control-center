//! Background commands of the explorer.
//!
//! They start as jobs of the job runner, are followed over a server-sent event stream
//! (`job_stream`), and stop on request, which ends the router process through `DELETE`.

use alloc::sync::Arc;
use std::sync::Mutex;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    jobs::{JobError, JobRecord, JobRunner},
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use kcc_rci::{RciClient, RciPath};
use serde_json::{Value, json};

use super::{OutputSlot, lock, request::Request};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record,
        context::{self, Target},
        gate::allowed,
        outcome::{Failure, Toast, ToastView},
    },
    system_pages::job_feed::may_act,
};

/// Prefix of the job kinds the explorer starts; `raw` jobs need `RawRci` to stop.
pub(crate) const KIND_PREFIX: &str = "explorer.";

/// The panel that follows one job.
#[derive(Debug, Clone)]
pub(crate) struct JobPanel {
    /// Job id.
    id: String,
    /// Event-stream URL.
    stream: String,
    /// Stop endpoint, when the user may stop the job.
    cancel: Option<String>,
}

impl JobPanel {
    /// Job id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Event-stream URL.
    pub(crate) fn stream(&self) -> &str {
        &self.stream
    }

    /// Stop endpoint.
    pub(crate) fn cancel(&self) -> Option<&str> {
        self.cancel.as_deref()
    }
}

/// Starts `request` on `target` as a job of `jobs`.
///
/// # Errors
///
/// Returns the failure to show when no job could start.
// NOT cancel-safe: once started, the job runs on.
pub(crate) async fn start(
    state: &WebState,
    target: Target<'_>,
    user: &CurrentUser,
    request: &Request,
) -> Result<JobPanel, Failure> {
    let locale = user.locale();
    let failed = |key: MessageKey, audit| Failure::new(tr(locale, key, None), audit);
    let jobs = state
        .advanced()
        .jobs()
        .cloned()
        .ok_or_else(|| failed(keys::WEB_EXPLORER_JOBS_UNAVAILABLE, "failed"))?;
    let router = target.router();
    let client = target
        .fleet()
        .registry()
        .client(router)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "explorer job: no router client");
            failed(keys::WEB_EXPLORER_UNREACHABLE, "unreachable")
        })?;
    let raw = request.risk() != Risk::Read;
    let kind = format!(
        "{KIND_PREFIX}{}.{}",
        if raw { "raw" } else { "read" },
        request.path().replace(' ', ".")
    );
    let slot: OutputSlot = Arc::new(Mutex::new(None));
    let work = Work {
        kind,
        router: router.to_owned(),
        client,
        path: request.path().to_owned(),
        body: request.body().clone(),
        slot: Arc::clone(&slot),
    };
    let id = work.run(&jobs).await.map_err(|error| {
        tracing::warn!(%error, "explorer job did not start");
        failed(keys::WEB_EXPLORER_FAILED, "failed")
    })?;
    state.advanced().keep_output(&id, user.username(), slot);
    Ok(JobPanel {
        stream: format!("/ui/sse/r/{router}/jobs/{id}"),
        cancel: (!raw || allowed(user, router, &[Permission::RawRci]))
            .then(|| format!("/ui/r/{router}/jobs/{id}/cancel")),
        id,
    })
}

/// What one job runs.
struct Work {
    /// Job kind.
    kind: String,
    /// Router profile id.
    router: String,
    /// The router's shared client.
    client: Arc<RciClient>,
    /// Catalog path.
    path: String,
    /// Validated body.
    body: Value,
    /// Where the final answer goes.
    slot: OutputSlot,
}

impl Work {
    /// Starts the work as a job of `jobs` and returns its id.
    ///
    /// # Errors
    ///
    /// Returns the job runner's refusal.
    // NOT cancel-safe: once started, the job runs on.
    async fn run(self, jobs: &Arc<JobRunner>) -> Result<String, JobError> {
        let Self {
            kind,
            router,
            client,
            path,
            body,
            slot,
        } = self;
        jobs.start(kind, Some(router), false, async move |job| {
            let segments: Vec<&str> = path.split_whitespace().collect();
            let resource =
                RciPath::from_segments(&segments).map_err(|_error| "invalid path".to_owned())?;
            let handle = client
                .start(resource, &body)
                .await
                .map_err(|error| error.to_string())?;
            let answer = handle
                .poll(&job.cancellation())
                .await
                .map_err(|error| error.to_string())?;
            *lock(&slot) = Some(answer);
            Ok(())
        })
        .await
    }
}

/// `POST /ui/r/{router}/jobs/{job}/cancel`: stops a running explorer job.
pub(crate) async fn cancel(
    State(state): State<WebState>,
    Path((router, job)): Path<(String, String)>,
    user: CurrentUser,
) -> Response {
    let Some(jobs) = state.advanced().jobs().cloned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(refusal) = context::target(&state, &user, &router).await {
        return refusal.status();
    }
    let Some(record) = explorer_job(&state, &user, &router, &job) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let raw = record.kind.starts_with("explorer.raw.");
    if raw && !allowed(&user, &router, &[Permission::RawRci]) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (toast, outcome) = match jobs.cancel(&job).await {
        Ok(()) => (
            Toast::success(user.locale(), keys::WEB_EXPLORER_JOB_STOPPED),
            "success",
        ),
        Err(_not_running) => (
            Toast::info(user.locale(), keys::WEB_EXPLORER_JOB_NOT_RUNNING),
            "not_running",
        ),
    };
    Record::on_router("web.explorer_job_cancel", &router, record.kind.clone())
        .with_params(json!({ "job": record.id }))
        .append(&state, &user, outcome)
        .await;
    errors::render(&ToastView::new(&toast, user.locale()))
}

/// The explorer job `job` of `router`, if it exists and `user` started it or may act on
/// every job of the router ([`may_act`]); any other job answers like a missing one.
pub(crate) fn explorer_job(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
    job: &str,
) -> Option<JobRecord> {
    let owner = state.advanced().output_owner(job);
    if !may_act(user, router, owner.as_deref()) {
        return None;
    }
    state.advanced().jobs()?.get(job).ok().filter(|record| {
        record.router.as_deref() == Some(router) && record.kind.starts_with(KIND_PREFIX)
    })
}
