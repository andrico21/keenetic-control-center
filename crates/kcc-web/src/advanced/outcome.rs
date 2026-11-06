//! What an execution shows: a headline, the problems that stopped it, the router's own
//! words when it refused, the response viewer or a background-job panel, a toast and the
//! header's unsaved badge.

use askama::Template;
use axum::{http::StatusCode, response::Response};
use fluent_bundle::FluentArgs;
use kcc_app::workflow::WorkflowError;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::RciError;

use super::{
    check::{Problem, sentence},
    context::fragment_shell,
    jobs::JobPanel,
    viewer::Viewer,
};
use crate::{
    errors,
    page::{Localize, Shell},
};

/// The result region of one execution.
#[derive(Default)]
pub(crate) struct Outcome {
    /// Notice tone: success, info or error.
    tone: &'static str,
    /// The localized headline.
    headline: String,
    /// Why the request was not sent.
    problems: Vec<String>,
    /// The router's own status messages when it refused.
    router_said: Vec<String>,
    /// The router's answer.
    viewer: Option<Viewer>,
    /// Download link of an answer too large for the page.
    download: Option<String>,
    /// A started background command.
    job: Option<JobPanel>,
    /// Whether the router now has unsaved changes.
    unsaved: bool,
    /// Success toast.
    toast: Option<String>,
    /// HTTP status; 422 for requests that were not sent.
    status: u16,
    /// Stable audit outcome id.
    audit: &'static str,
}

/// The outcome fragment.
#[derive(Template)]
#[template(path = "partials/explorer_outcome.html")]
struct OutcomeView {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
}

impl Localize for OutcomeView {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// Why an execution failed, in the user's words.
pub(crate) struct Failure {
    /// Localized explanation.
    message: String,
    /// The router's own status messages.
    router_said: Vec<String>,
    /// Stable audit outcome id.
    audit: &'static str,
}

impl Failure {
    /// A failure explained by `message`, audited as `audit`.
    pub(crate) const fn new(message: String, audit: &'static str) -> Self {
        Self {
            message,
            router_said: Vec::new(),
            audit,
        }
    }

    /// Adds the router's own words.
    pub(crate) fn with_router_said(mut self, messages: Vec<String>) -> Self {
        self.router_said = messages;
        self
    }

    /// Localized explanation.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl Outcome {
    /// A request that was not sent because of `problems`.
    pub(crate) fn invalid(locale: Locale, problems: &[Problem]) -> Self {
        Self {
            tone: "error",
            headline: tr(locale, keys::WEB_EXPLORER_INVALID, None),
            problems: problems
                .iter()
                .map(|problem| sentence(locale, problem))
                .collect(),
            status: 422,
            audit: "validation_failed",
            ..Self::default()
        }
    }

    /// A request the router or the workflow refused.
    pub(crate) fn failed(failure: Failure) -> Self {
        Self {
            tone: "error",
            headline: failure.message,
            router_said: failure.router_said,
            status: 200,
            audit: failure.audit,
            ..Self::default()
        }
    }

    /// A completed command and the router's answer.
    pub(crate) fn done(locale: Locale, viewer: Viewer, unsaved: bool) -> Self {
        let key = if unsaved {
            keys::WEB_EXPLORER_DONE_UNSAVED
        } else {
            keys::WEB_EXPLORER_DONE
        };
        let headline = tr(locale, key, None);
        Self {
            tone: "success",
            toast: Some(headline.clone()),
            headline,
            viewer: Some(viewer),
            unsaved,
            status: 200,
            audit: "success",
            ..Self::default()
        }
    }

    /// A started background command.
    pub(crate) fn job(locale: Locale, panel: JobPanel) -> Self {
        Self {
            tone: "info",
            headline: tr(locale, keys::WEB_EXPLORER_JOB_STARTED, None),
            job: Some(panel),
            status: 200,
            audit: "started",
            ..Self::default()
        }
    }

    /// Offers the complete answer at `href`.
    pub(crate) fn with_download(mut self, href: String) -> Self {
        self.download = Some(href);
        self
    }

    /// Shows the router's answer under a failure, such as a partly applied batch.
    pub(crate) fn with_viewer(mut self, viewer: Viewer) -> Self {
        self.viewer = Some(viewer);
        self
    }

    /// Stable audit outcome id.
    pub(crate) const fn audit(&self) -> &'static str {
        self.audit
    }

    /// The outcome fragment in `locale`.
    pub(crate) fn render(self, locale: Locale) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);
        let page = OutcomeView {
            shell: fragment_shell(locale),
            outcome: self,
        };
        let mut response = errors::render(&page);
        if response.status() == StatusCode::OK {
            *response.status_mut() = status;
        }
        response
    }
}

/// The failure of a change-workflow error.
pub(crate) fn workflow_failure(locale: Locale, error: &WorkflowError) -> Failure {
    match error {
        WorkflowError::Rci(rci) => rci_failure(locale, rci),
        WorkflowError::RouterBusy { actor } => {
            let mut args = FluentArgs::new();
            args.set("user", actor.clone());
            Failure::new(tr(locale, keys::WEB_SAVE_BUSY, Some(&args)), "busy")
        }
        WorkflowError::Conflict { agent: _ } => {
            Failure::new(tr(locale, keys::WEB_EXPLORER_CONFLICT, None), "conflict")
        }
        WorkflowError::PermissionDenied { router: _ } => {
            Failure::new(tr(locale, keys::ERRORS_FORBIDDEN, None), "forbidden")
        }
        WorkflowError::CatalogValidation { issues } => Failure::new(
            issues
                .iter()
                .map(|issue| sentence(locale, &Problem::Issue(issue.clone())))
                .collect::<Vec<_>>()
                .join(" "),
            "validation_failed",
        ),
        WorkflowError::VerificationFailed { field: _ }
        | WorkflowError::State(_)
        | WorkflowError::Registry(_)
        | WorkflowError::Backup(_)
        | WorkflowError::Audit(_)
        | WorkflowError::InvalidResponse
        | WorkflowError::SaveTimeout
        | _ => {
            tracing::error!(%error, "explorer change failed");
            Failure::new(tr(locale, keys::WEB_EXPLORER_FAILED, None), "failed")
        }
    }
}

/// The failure of an RCI error; an error status carries the router's message.
pub(crate) fn rci_failure(locale: Locale, error: &RciError) -> Failure {
    match error {
        RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message,
        } => Failure::new(tr(locale, keys::WEB_EXPLORER_REJECTED, None), "rci_error")
            .with_router_said(vec![message.clone()]),
        RciError::Transport | RciError::Policy => Failure::new(
            tr(locale, keys::WEB_EXPLORER_UNREACHABLE, None),
            "unreachable",
        ),
        RciError::Timeout => Failure::new(tr(locale, keys::ERRORS_TIMEOUT, None), "timeout"),
        RciError::NotFound => {
            Failure::new(tr(locale, keys::WEB_EXPLORER_NOT_FOUND, None), "rci_error")
        }
        RciError::Auth(_) => Failure::new(tr(locale, keys::ERRORS_ROUTER_AUTH, None), "rci_error"),
        RciError::Http { status: _ }
        | RciError::MethodNotAllowed
        | RciError::BodyTooLarge
        | RciError::Decode
        | RciError::Validation
        | _ => {
            tracing::warn!(?error, "explorer request failed");
            Failure::new(tr(locale, keys::WEB_EXPLORER_FAILED, None), "rci_error")
        }
    }
}
