//! Advanced router access: the catalog-driven command explorer, the RCI console and the
//! CLI console, their background jobs and the live job streams.
//!
//! Routes (all behind CSRF, authentication and the route-table authorization):
//!
//! - `GET /ui/advanced`: the routers the user may open, with explorer and console links.
//! - `/ui/r/{router}/explorer[...]`: search, group tree, command detail with the form
//!   generated from the command's JSON Schema, preview, execution, the router's stored
//!   lines and the download of the last large response (route table: `Read`; every
//!   execution re-checks the permission its catalog risk needs).
//! - `/ui/r/{router}/console/{rci,cli}[...]`: the raw consoles (route table: `RawRci`).
//! - `/ui/r/{router}/jobs/{job}/cancel` and `/ui/sse/r/{router}/jobs/{job}`: stopping and
//!   following background commands.
//!
//! Every request is validated against the router's catalog before anything is sent;
//! changes run through the change workflow (backup, conflict check, audit) and the
//! router's answer is shown in the response viewer.

mod check;
mod cli;
mod deliver;
mod detail;
mod execute;
mod explorer;
mod form;
mod job_stream;
mod jobs;
mod landing;
mod lookup;
mod meta;
mod outcome;
mod preview;
mod rci;
mod rci_check;
mod request;
mod types;
mod viewer;

use alloc::{collections::VecDeque, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::{
    Router,
    routing::{get, post},
};
use kcc_app::jobs::JobRunner;
use kcc_rci::RciBody;

use crate::{WebState, system_pages::job_feed::JobFeeds};

/// Sessions whose last large response is kept for download.
const STORED_RESPONSES: usize = 8;

/// Explorer jobs whose output is kept for their listeners.
const STORED_OUTPUTS: usize = 32;

/// Where a job leaves the router's final answer.
type OutputSlot = Arc<Mutex<Option<RciBody>>>;

/// The services and short-lived state of the advanced pages.
pub(crate) struct Services {
    /// The last response too large for its page, per session and router.
    responses: Mutex<VecDeque<Stored>>,
    /// The output slots of recent explorer jobs, by job id.
    outputs: Mutex<VecDeque<(String, OutputSlot)>>,
    /// Runs background commands; `None` refuses them with a notice.
    jobs: Option<Arc<JobRunner>>,
    /// The kept progress of the jobs the system pages start.
    feeds: JobFeeds,
}

/// One response kept for download.
struct Stored {
    /// Opaque session key.
    session: String,
    /// Router profile id.
    router: String,
    /// Response text as the viewer shows it, secrets redacted.
    body: Arc<str>,
    /// Whether the body is JSON (else plain text).
    json: bool,
}

impl Services {
    /// Services with `jobs` running background commands.
    pub(crate) const fn new(jobs: Option<Arc<JobRunner>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            outputs: Mutex::new(VecDeque::new()),
            jobs,
            feeds: JobFeeds::new(),
        }
    }

    /// The job runner, when attached.
    pub(crate) const fn jobs(&self) -> Option<&Arc<JobRunner>> {
        self.jobs.as_ref()
    }

    /// The kept progress of the jobs the system pages start.
    pub(crate) const fn feeds(&self) -> &JobFeeds {
        &self.feeds
    }

    /// Keeps `body` as the downloadable response of `session` on `router`.
    fn keep_response(&self, session: &str, router: &str, body: Arc<str>, json: bool) {
        let mut stored = lock(&self.responses);
        stored.retain(|entry| entry.session != session || entry.router != router);
        if stored.len() >= STORED_RESPONSES {
            drop(stored.pop_front());
        }
        stored.push_back(Stored {
            session: session.to_owned(),
            router: router.to_owned(),
            body,
            json,
        });
    }

    /// The downloadable response of `session` on `router` and whether it is JSON.
    fn response(&self, session: &str, router: &str) -> Option<(Arc<str>, bool)> {
        lock(&self.responses)
            .iter()
            .find(|entry| entry.session == session && entry.router == router)
            .map(|entry| (Arc::clone(&entry.body), entry.json))
    }

    /// Registers the output slot of job `id`.
    fn keep_output(&self, id: &str, slot: OutputSlot) {
        let mut outputs = lock(&self.outputs);
        if outputs.len() >= STORED_OUTPUTS {
            drop(outputs.pop_front());
        }
        outputs.push_back((id.to_owned(), slot));
    }

    /// The router's final answer to job `id`, once it finished.
    fn output(&self, id: &str) -> Option<RciBody> {
        let slot = lock(&self.outputs)
            .iter()
            .find(|(job, _)| job == id)
            .map(|(_, slot)| Arc::clone(slot))?;
        lock(&slot).clone()
    }
}

/// The page and action routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/advanced", get(landing::page))
        .route("/ui/r/{router}/explorer", get(explorer::page))
        .route("/ui/r/{router}/explorer/search", get(explorer::search))
        .route("/ui/r/{router}/explorer/group", get(explorer::group))
        .route("/ui/r/{router}/explorer/command", get(explorer::command))
        .route("/ui/r/{router}/explorer/stored", get(preview::stored))
        .route("/ui/r/{router}/explorer/response", get(preview::download))
        .route("/ui/r/{router}/explorer/preview", post(preview::preview))
        .route("/ui/r/{router}/explorer/execute", post(execute::execute))
        .route("/ui/r/{router}/jobs/{job}/cancel", post(jobs::cancel))
        .route("/ui/r/{router}/console/rci", get(rci::page))
        .route("/ui/r/{router}/console/rci/check", post(rci::validate))
        .route("/ui/r/{router}/console/rci/send", post(rci::send))
        .route("/ui/r/{router}/console/cli", get(cli::page))
        .route("/ui/r/{router}/console/cli/check", post(cli::validate))
        .route("/ui/r/{router}/console/cli/send", post(cli::send))
}

/// The event-stream routes, merged outside the request timeout.
pub(crate) fn streams() -> Router<WebState> {
    Router::new().route("/ui/sse/r/{router}/jobs/{job}", get(job_stream::stream))
}

/// A short-lived lock; a panic while holding it cannot leave an entry half-written, so a
/// poisoned lock is used as is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use alloc::sync::Arc;

    use super::{STORED_RESPONSES, Services};

    #[test]
    fn kept_responses_belong_to_one_session_and_router() {
        let services = Services::new(None);
        services.keep_response("alpha", "home", Arc::from("{\"a\":1}"), true);
        services.keep_response("beta", "home", Arc::from("text"), false);
        assert_eq!(
            services
                .response("alpha", "home")
                .map(|(body, json)| (body.to_string(), json)),
            Some(("{\"a\":1}".to_owned(), true)),
            "own response"
        );
        assert!(
            services.response("alpha", "cottage").is_none(),
            "other router"
        );
        assert!(
            services.response("gamma", "home").is_none(),
            "other session"
        );
        services.keep_response("alpha", "home", Arc::from("newer"), false);
        assert_eq!(
            services
                .response("alpha", "home")
                .map(|(body, _)| body.to_string()),
            Some("newer".to_owned()),
            "replaced"
        );
        for index in 0..STORED_RESPONSES {
            services.keep_response(&format!("session-{index}"), "home", Arc::from("x"), false);
        }
        assert!(
            services.response("beta", "home").is_none(),
            "oldest evicted"
        );
    }
}
