//! The live stream of one explorer job: its status changes, then the router's final
//! answer, then a `done` event that closes the browser's event source.

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
    jobs::{JobEvent, JobStatus},
    permissions::Permission,
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::{
    jobs::explorer_job,
    viewer::{Rendered, Viewer},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    job_status,
    overview::{fragment, guarded},
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, fragment_shell},
        gate::allowed,
    },
    stream_session::StreamSession,
};

/// The router's final answer to a job.
#[derive(Template)]
#[template(path = "partials/explorer_job_output.html")]
struct OutputView {
    /// Locale carrier.
    shell: Shell,
    /// The answer, when the job completed.
    viewer: Option<Viewer>,
    /// Why there is no answer.
    note: MessageKey,
}

localized!(OutputView);

/// `GET /ui/sse/r/{router}/jobs/{job}`: the job's status changes, then the router's
/// final answer and a `done` event that closes the stream.
// cancel-safe: it only checks access and returns the job's event stream.
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
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let receiver = jobs.subscribe();
    let Some(record) = explorer_job(&state, &user, &router, &job) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let events = Events {
        state: state.clone(),
        locale: user.locale(),
        reveal: allowed(&user, &router, &[Permission::RevealSecrets]),
        id: record.id.clone(),
    };
    guarded(events.stream(receiver, record.status), slot).into_response()
}

/// What a job stream renders.
struct Events {
    /// Services, for the job's answer.
    state: WebState,
    /// Listener locale.
    locale: Locale,
    /// Whether the listener may see the secrets in the answer.
    reveal: bool,
    /// Job id.
    id: String,
}

impl Events {
    /// The events of a job now in `status`: the current status, then one status per
    /// change until it ends, then its answer and `done`.
    fn stream(self, receiver: Receiver<JobEvent>, status: JobStatus) -> BoxStream<'static, Event> {
        let opening = stream::iter([self.status(status)]);
        if terminal(status) {
            return opening.chain(stream::iter(self.ending(status))).boxed();
        }
        let updates = stream::unfold(Some((receiver, self)), async |held| {
            let (mut inbox, events) = held?;
            loop {
                match inbox.recv().await {
                    Ok(event) if event.id == events.id => {
                        if terminal(event.status) {
                            let ending = events.ending(event.status);
                            return Some((stream::iter(ending), None));
                        }
                        let update = vec![events.status(event.status)];
                        return Some((stream::iter(update), Some((inbox, events))));
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return None,
                }
            }
        })
        .flatten();
        opening.chain(updates).boxed()
    }

    /// A `status` event.
    fn status(&self, status: JobStatus) -> Event {
        job_status::event(status, self.locale)
    }

    /// The final events: the answer, the final status and `done`.
    fn ending(&self, status: JobStatus) -> Vec<Event> {
        let answer = self.state.advanced().output(&self.id);
        let viewer = answer
            .filter(|_| status == JobStatus::Completed)
            .map(|body| {
                Rendered::body(&body, self.reveal, self.locale)
                    .into_parts()
                    .0
            });
        let note = match status {
            JobStatus::Cancelled => keys::WEB_EXPLORER_JOB_CANCELLED,
            JobStatus::Completed => keys::WEB_EXPLORER_EMPTY_RESPONSE,
            JobStatus::Running | JobStatus::Failed | JobStatus::Interrupted | _ => {
                keys::WEB_EXPLORER_JOB_FAILED_TEXT
            }
        };
        vec![
            fragment(
                "output",
                &OutputView {
                    shell: fragment_shell(self.locale),
                    viewer,
                    note,
                },
            ),
            self.status(status),
            Event::default().event("done").data("done"),
        ]
    }
}

/// Whether a job in `status` has ended.
const fn terminal(status: JobStatus) -> bool {
    !matches!(status, JobStatus::Running)
}
