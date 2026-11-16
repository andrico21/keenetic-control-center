//! The jobs the system pages start: the panel that follows one, its live stream and Stop.
//!
//! A diagnostic runs as a job of the job runner, and so does the component commit, which
//! restarts the router and waits until it answers again. The panel connects to
//! `GET /ui/sse/r/{router}/system/jobs/{job}`, which sends every line the job reported
//! from the beginning (kept by `job_feed`), each status change, and `done` when the job
//! ended. `POST /ui/r/{router}/system/jobs/{job}/cancel` stops a diagnostic: the job's
//! cancellation ends the router process through `DELETE`.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response, sse::Event},
};
use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use kcc_app::jobs::{JobProgress, JobRecord, JobRunner, JobStatus};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde_json::json;
use tokio::sync::watch;

use super::{component_commit::phase_line, diagnostic_lines::sentence, job_feed::JobView};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    overview::{fragment, guarded},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record,
        context::{self, fragment_shell},
        outcome::{Toast, ToastView},
    },
    stream_session::StreamSession,
};

/// Kind prefix of the diagnostic jobs.
pub(crate) const DIAGNOSTICS: &str = "diagnostics.";

/// Kind of the component commit job.
pub(crate) const COMMIT: &str = "components.commit";

/// The panel following one job.
#[derive(Template)]
#[template(path = "partials/system_job.html")]
pub(crate) struct JobPanel {
    /// Locale carrier.
    shell: Shell,
    /// Job id.
    id: String,
    /// The panel title.
    title: MessageKey,
    /// Event-stream URL.
    stream: String,
    /// Stop endpoint, when the job can be stopped.
    cancel: Option<String>,
}

localized!(JobPanel);

impl JobPanel {
    /// The panel of job `id` on `router`, with Stop.
    pub(crate) fn new(locale: Locale, router: &str, id: String) -> Self {
        Self {
            shell: fragment_shell(locale),
            stream: format!("/ui/sse/r/{router}/system/jobs/{id}"),
            cancel: Some(format!("/ui/r/{router}/system/jobs/{id}/cancel")),
            id,
            title: keys::WEB_SYSTEM_JOB_TITLE,
        }
    }

    /// Titles the panel `title`.
    pub(crate) const fn titled(mut self, title: MessageKey) -> Self {
        self.title = title;
        self
    }

    /// The panel without Stop, for a job that cannot stop halfway.
    pub(crate) fn unstoppable(mut self) -> Self {
        self.cancel = None;
        self
    }

    /// The panel, the answer to the request that started the job.
    pub(crate) fn answer(&self) -> Response {
        errors::render(self)
    }
}

/// The status pill of a job.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<span class=\"status\" data-status=\"{{ status }}\">{{ t(*label) }}</span>"
)]
struct StatusView {
    /// Locale carrier.
    shell: Shell,
    /// `data-status` value.
    status: &'static str,
    /// Label.
    label: MessageKey,
}

/// One line of a job's output.
#[derive(Template)]
#[template(ext = "html", source = "<li class=\"job-lines__line\">{{ text }}</li>")]
struct LineView {
    /// Locale carrier.
    shell: Shell,
    /// The line, localized.
    text: String,
}

localized!(StatusView);

localized!(LineView);

/// The job `job` of `router` when a system page started it.
pub(crate) fn followed(jobs: &JobRunner, router: &str, job: &str) -> Option<JobRecord> {
    jobs.get(job).ok().filter(|record| {
        record.router.as_deref() == Some(router)
            && (record.kind.starts_with(DIAGNOSTICS) || record.kind == COMMIT)
    })
}

/// `GET /ui/sse/r/{router}/system/jobs/{job}`: every line the job reported, its status
/// changes, then `done`.
pub(crate) async fn stream(
    State(state): State<WebState>,
    Path((router, job)): Path<(String, String)>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let Some(jobs) = state.advanced().jobs().cloned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(refusal) = context::target(&state, &user, &router).await {
        return refusal.status();
    }
    let Some(record) = followed(&jobs, &router, &job) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(feed) = state.advanced().feeds().get(&record.id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    guarded(events(feed, user.locale()), slot).into_response()
}

/// Where a job stream is: the job's progress, the lines sent, the status shown, whether
/// it is the first round, and the listener's locale.
type Cursor = (
    watch::Receiver<JobView>,
    usize,
    Option<JobStatus>,
    bool,
    Locale,
);

/// The events of a job from `feed`: everything so far, then each change, until it ends.
fn events(progress: watch::Receiver<JobView>, listener: Locale) -> BoxStream<'static, Event> {
    let start: Option<Cursor> = Some((progress, 0, None, true, listener));
    stream::unfold(start, async |held| {
        let (mut feed, sent, shown, first, locale) = held?;
        let open = first || feed.changed().await.is_ok();
        let view = feed.borrow_and_update().clone();
        let mut out: Vec<Event> = view
            .details()
            .iter()
            .skip(sent)
            .filter_map(|detail| line(detail, locale))
            .map(|text| {
                fragment(
                    "line",
                    &LineView {
                        shell: fragment_shell(locale),
                        text,
                    },
                )
            })
            .collect();
        if shown != Some(view.status()) {
            out.push(status(view.status(), locale));
        }
        if !open || view.status() != JobStatus::Running {
            out.push(Event::default().event("done").data("done"));
            return Some((stream::iter(out), None));
        }
        let next = (
            feed,
            view.details().len(),
            Some(view.status()),
            false,
            locale,
        );
        Some((stream::iter(out), Some(next)))
    })
    .flatten()
    .boxed()
}

/// A job's detail as one localized line; details no page reads are left out.
fn line(detail: &JobProgress, locale: Locale) -> Option<String> {
    match detail {
        JobProgress::Structured(value) => phase_line(value, locale),
        JobProgress::OutputLine(text) => sentence(text, locale),
        _ => None,
    }
}

/// A `status` event.
fn status(status: JobStatus, locale: Locale) -> Event {
    let (value, label) = match status {
        JobStatus::Running => ("running", keys::WEB_EXPLORER_JOB_RUNNING),
        JobStatus::Completed => ("done", keys::WEB_EXPLORER_JOB_COMPLETED),
        JobStatus::Cancelled => ("failed", keys::WEB_EXPLORER_JOB_CANCELLED_LABEL),
        JobStatus::Failed | JobStatus::Interrupted | _ => ("failed", keys::WEB_EXPLORER_JOB_FAILED),
    };
    fragment(
        "status",
        &StatusView {
            shell: fragment_shell(locale),
            status: value,
            label,
        },
    )
}

/// `POST /ui/r/{router}/system/jobs/{job}/cancel`: stops a running diagnostic.
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
    let Some(record) =
        followed(&jobs, &router, &job).filter(|found| found.kind.starts_with(DIAGNOSTICS))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
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
    Record::on_router("web.diagnostics_cancel", &router, record.kind.clone())
        .with_params(json!({ "job": record.id }))
        .append(&state, &user, outcome)
        .await;
    errors::render(&ToastView::new(&toast, user.locale()))
}
