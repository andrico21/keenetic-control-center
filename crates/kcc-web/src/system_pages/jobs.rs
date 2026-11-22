//! The jobs the system pages start: the panel that follows one, its live stream and Stop.
//!
//! A diagnostic runs as a job of the job runner, and so do the component commit, which
//! restarts the router and waits until it answers again, and the Entware setup, whose last
//! line offers to save the configuration it left unsaved. The panel connects to
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
use kcc_app::{
    jobs::{JobProgress, JobRecord, JobStatus},
    permissions::Permission,
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde_json::json;
use tokio::sync::watch;

use super::{
    component_commit::phase_line,
    diagnostic_lines::sentence,
    entware_setup::step_line,
    job_feed::{JobView, may_act},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors, job_status,
    overview::{fragment, guarded},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record,
        context::{self, fragment_shell},
        gate::allowed,
        outcome::{Toast, ToastView},
    },
    stream_session::StreamSession,
};

/// Kind prefix of the diagnostic jobs.
pub(crate) const DIAGNOSTICS: &str = "diagnostics.";

/// Kind of the component commit job.
pub(crate) const COMMIT: &str = "components.commit";

/// Kind of the Entware setup job.
pub(crate) const SETUP: &str = "entware.setup";

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

/// One line of a job's output; the last line of a job that left the configuration unsaved
/// offers Save.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<li class=\"job-lines__line\">{{ text }}{% if let Some(href) = save %} <button class=\"button button--primary\" type=\"button\" hx-post=\"{{ href }}\" hx-target=\"#toasts\" hx-swap=\"beforeend\">{{ t(keys::WEB_UNSAVED_SAVE) }}</button>{% endif %}</li>"
)]
struct LineView {
    /// Locale carrier.
    shell: Shell,
    /// The line, localized.
    text: String,
    /// The router's save endpoint, offered after this line.
    save: Option<String>,
}

localized!(LineView);

/// The job `job` of `router` when a system page started it and `user` started it or may
/// act on every job of the router ([`may_act`]); any other job answers like a missing one.
pub(crate) fn followed(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
    job: &str,
) -> Option<JobRecord> {
    let owner = state.advanced().feeds().owner(job);
    if !may_act(user, router, owner.as_deref()) {
        return None;
    }
    state.advanced().jobs()?.get(job).ok().filter(|record| {
        record.router.as_deref() == Some(router)
            && (record.kind.starts_with(DIAGNOSTICS)
                || record.kind == COMMIT
                || record.kind == SETUP)
    })
}

/// `GET /ui/sse/r/{router}/system/jobs/{job}`: every line the job reported, its status
/// changes, then `done`.
// cancel-safe: it only checks access and returns the job's event stream.
pub(crate) async fn stream(
    State(state): State<WebState>,
    Path((router, job)): Path<(String, String)>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    if state.advanced().jobs().is_none() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if let Err(refusal) = context::target(&state, &user, &router).await {
        return refusal.status();
    }
    let Some(record) = followed(&state, &user, &router, &job) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(feed) = state.advanced().feeds().get(&record.id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let save = allowed(&user, &router, &[Permission::Save]).then(|| format!("/ui/r/{router}/save"));
    let listener = Listener {
        locale: user.locale(),
        save,
    };
    guarded(events(feed, listener), slot).into_response()
}

/// Who follows a job stream: their locale, and the router's save endpoint when they may
/// save.
#[derive(Clone)]
struct Listener {
    /// The listener's locale.
    locale: Locale,
    /// The router's save endpoint, when the listener holds `Save` on it.
    save: Option<String>,
}

/// Where a job stream is: the job's progress, the lines sent, the status shown, whether
/// it is the first round, and the listener.
type Cursor = (
    watch::Receiver<JobView>,
    usize,
    Option<JobStatus>,
    bool,
    Listener,
);

/// The events of a job from `feed`: everything so far, then each change, until it ends.
fn events(progress: watch::Receiver<JobView>, follower: Listener) -> BoxStream<'static, Event> {
    let start: Option<Cursor> = Some((progress, 0, None, true, follower));
    stream::unfold(start, async |held| {
        let (mut feed, sent, shown, first, listener) = held?;
        let locale = listener.locale;
        let open = first || feed.changed().await.is_ok();
        let view = feed.borrow_and_update().clone();
        let mut out: Vec<Event> = view
            .details()
            .iter()
            .skip(sent)
            .filter_map(|detail| line(detail, locale))
            .map(|(text, saves)| {
                fragment(
                    "line",
                    &LineView {
                        shell: fragment_shell(locale),
                        text,
                        save: listener.save.clone().filter(|_| saves),
                    },
                )
            })
            .collect();
        if shown != Some(view.status()) {
            out.push(job_status::event(view.status(), locale));
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
            listener,
        );
        Some((stream::iter(out), Some(next)))
    })
    .flatten()
    .boxed()
}

/// A job's detail as one localized line, and whether Save follows it; details no page
/// reads are left out.
fn line(detail: &JobProgress, locale: Locale) -> Option<(String, bool)> {
    match detail {
        JobProgress::Structured(value) => phase_line(value, locale)
            .map(|said| (said, false))
            .or_else(|| step_line(value, locale)),
        JobProgress::OutputLine(output) => sentence(output, locale).map(|said| (said, false)),
        _ => None,
    }
}

/// `POST /ui/r/{router}/system/jobs/{job}/cancel`: stops a running diagnostic.
// NOT cancel-safe: the job may be cancelled, and its audit entry queued, before the future is
// dropped.
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
        followed(&state, &user, &router, &job).filter(|found| found.kind.starts_with(DIAGNOSTICS))
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
