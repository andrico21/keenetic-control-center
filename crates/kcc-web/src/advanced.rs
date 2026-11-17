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
#[cfg(test)]
mod console_forms_tests;
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
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use axum::{
    Router,
    routing::{get, post},
};
use kcc_app::jobs::JobRunner;
use kcc_rci::RciBody;

use crate::{WebState, sync::lock, system_pages::job_feed::JobFeeds};

/// Large responses kept for download per user; a user over it loses their own oldest.
const STORED_RESPONSES: usize = 8;

/// Explorer jobs whose output is kept per user for their listeners; a user over it loses
/// their own oldest finished job's slot, never a running job's.
const STORED_OUTPUTS: usize = 32;

/// Where a job leaves the router's final answer.
pub(crate) struct Output {
    /// The router's answer, once the job completed.
    answer: Mutex<Option<RciBody>>,
    /// Whether the job ended, whatever the outcome; only an ended slot may be evicted.
    ended: AtomicBool,
}

impl Output {
    /// A slot of a job that is still running.
    pub(crate) const fn new() -> Self {
        Self {
            answer: Mutex::new(None),
            ended: AtomicBool::new(false),
        }
    }

    /// Keeps the job's final answer.
    pub(crate) fn keep(&self, answer: RciBody) {
        *lock(&self.answer) = Some(answer);
    }

    /// Marks the job as ended; its slot may now be evicted.
    pub(crate) fn end(&self) {
        self.ended.store(true, Ordering::Release);
    }

    /// Whether the job ended.
    fn is_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }
}

/// A shared output slot.
type OutputSlot = Arc<Output>;

/// The services and short-lived state of the advanced pages.
pub(crate) struct Services {
    /// The last response too large for its page, per session and router.
    responses: Mutex<VecDeque<Stored>>,
    /// The recent explorer jobs: id, the username that started it and its output slot.
    outputs: Mutex<VecDeque<(String, String, OutputSlot)>>,
    /// Runs background commands; `None` refuses them with a notice.
    jobs: Option<Arc<JobRunner>>,
    /// The kept progress of the jobs the system pages start.
    feeds: JobFeeds,
}

/// One response kept for download.
struct Stored {
    /// The username that obtained it; the per-user cap counts these.
    owner: String,
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

    /// Keeps `body` as the downloadable response of `session` on `router`, obtained by
    /// `owner`. A user over the cap loses their own oldest response, nobody else's.
    fn keep_response(
        &self,
        (owner, session): (&str, &str),
        router: &str,
        body: Arc<str>,
        json: bool,
    ) {
        let mut stored = lock(&self.responses);
        stored.retain(|entry| entry.session != session || entry.router != router);
        while stored.iter().filter(|entry| entry.owner == owner).count() >= STORED_RESPONSES {
            let Some(oldest) = stored.iter().position(|entry| entry.owner == owner) else {
                break;
            };
            drop(stored.remove(oldest));
        }
        stored.push_back(Stored {
            owner: owner.to_owned(),
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

    /// Registers job `id`, started by `owner`, and its output slot. A user over the cap
    /// loses their own oldest ended job's slot; a running job's slot is never evicted.
    fn keep_output(&self, id: &str, owner: &str, slot: OutputSlot) {
        let mut outputs = lock(&self.outputs);
        while outputs.iter().filter(|(_, who, _)| who == owner).count() >= STORED_OUTPUTS {
            let Some(oldest) = outputs
                .iter()
                .position(|(_, who, held)| who == owner && held.is_ended())
            else {
                break;
            };
            drop(outputs.remove(oldest));
        }
        outputs.push_back((id.to_owned(), owner.to_owned(), slot));
    }

    /// The username that started explorer job `id`, while it is kept.
    fn output_owner(&self, id: &str) -> Option<String> {
        lock(&self.outputs)
            .iter()
            .find(|(job, _, _)| job == id)
            .map(|(_, owner, _)| owner.clone())
    }

    /// The router's final answer to job `id`, once it finished.
    fn output(&self, id: &str) -> Option<RciBody> {
        let slot = lock(&self.outputs)
            .iter()
            .find(|(job, _, _)| job == id)
            .map(|(_, _, slot)| Arc::clone(slot))?;
        lock(&slot.answer).clone()
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

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use alloc::sync::Arc;

    use super::{Output, STORED_OUTPUTS, STORED_RESPONSES, Services};

    /// W4-07: one user's flood of downloads evicts only that user's own oldest ones.
    #[test]
    fn a_flood_of_downloads_leaves_other_users_downloads() {
        let services = Services::new(None);
        services.keep_response(("bea", "session-b"), "home", Arc::from("b's"), false);
        for index in 0..STORED_RESPONSES * 3 {
            services.keep_response(
                ("ann", &format!("flood-{index}")),
                "home",
                Arc::from("x"),
                false,
            );
        }
        assert!(
            services.response("session-b", "home").is_some(),
            "another user's download survives the flood"
        );
    }

    /// W4-07: a flood of jobs never evicts a running job's slot, another user's or the
    /// flooder's own; the flooder's own oldest ended slots go first.
    #[test]
    fn a_flood_of_jobs_leaves_running_jobs_answers() {
        let services = Services::new(None);
        services.keep_output("b-job", "bea", Arc::new(Output::new()));
        services.keep_output("a-running", "ann", Arc::new(Output::new()));
        for index in 0..STORED_OUTPUTS * 3 {
            let finished = Arc::new(Output::new());
            finished.end();
            services.keep_output(&format!("flood-{index}"), "ann", finished);
        }
        for (job, owner) in [("b-job", "bea"), ("a-running", "ann")] {
            assert_eq!(
                services.output_owner(job).as_deref(),
                Some(owner),
                "{job} stays known to its owner"
            );
        }
        assert!(
            services.output_owner("flood-0").is_none(),
            "the oldest ended slot of the flooder went first"
        );
        assert!(
            services
                .output_owner(&format!("flood-{}", STORED_OUTPUTS * 3 - 1))
                .is_some(),
            "the newest is kept"
        );
    }

    #[test]
    fn kept_responses_belong_to_one_session_and_router() {
        let services = Services::new(None);
        services.keep_response(("user", "alpha"), "home", Arc::from("{\"a\":1}"), true);
        services.keep_response(("user", "beta"), "home", Arc::from("text"), false);
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
        services.keep_response(("user", "alpha"), "home", Arc::from("newer"), false);
        assert_eq!(
            services
                .response("alpha", "home")
                .map(|(body, _)| body.to_string()),
            Some("newer".to_owned()),
            "replaced"
        );
        for index in 0..STORED_RESPONSES {
            services.keep_response(
                ("user", &format!("session-{index}")),
                "home",
                Arc::from("x"),
                false,
            );
        }
        assert!(
            services.response("beta", "home").is_none(),
            "oldest evicted"
        );
    }
}
