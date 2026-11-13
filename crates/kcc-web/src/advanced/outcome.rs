//! What an execution shows.
//!
//! The kit's outcome (headline, problems, the router's own words, toast and unsaved
//! badge) with the router's answer in the response viewer, a download link for an answer
//! too large for the page, or a background-job panel.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    check::{Problem, sentence},
    jobs::JobPanel,
    viewer::Viewer,
};
use crate::{
    errors,
    page::{Localize, Shell},
    page_kit::{
        context::fragment_shell,
        family::Family,
        outcome::{Failure, Outcome, with_status},
    },
};

/// What a completed request left for the configuration save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Left {
    /// Nothing: a read, or a change after which the router's state is unknown.
    Nothing,
    /// A change that waits for a save.
    Unsaved,
    /// A change the router saved at once.
    Stored,
    /// A change with some leaf commands stored at once and the rest waiting for a save.
    Mixed(Vec<String>),
}

impl Left {
    /// What a change left: the workflow's `unsaved`, unless the router persisted all of
    /// it at once.
    pub(crate) fn of(unsaved: bool, persists: bool, persisted_paths: Vec<String>) -> Self {
        match (persists, unsaved) {
            (true, _) => Self::Stored,
            (false, true) if persisted_paths.is_empty() => Self::Unsaved,
            (false, true) => Self::Mixed(persisted_paths),
            (false, false) => Self::Nothing,
        }
    }

    /// The headline and audit outcome of a batch whose router answered `succeeded` items
    /// and refused `failed`, by what the successful items left.
    pub(crate) fn partial(
        &self,
        locale: Locale,
        succeeded: usize,
        failed: usize,
    ) -> (String, &'static str) {
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("succeeded", succeeded);
        args.set("failed", failed);
        let (key, audit) = match self {
            Self::Stored => (
                keys::WEB_EXPLORER_PARTIAL_PERSISTED,
                "partially_applied_persisted",
            ),
            Self::Mixed(paths) => {
                args.set("paths", paths.join(", "));
                (
                    keys::WEB_EXPLORER_PARTIAL_MIXED,
                    "partially_applied_unsaved",
                )
            }
            Self::Unsaved => (
                keys::WEB_EXPLORER_PARTIAL_UNSAVED,
                "partially_applied_unsaved",
            ),
            // A read-only batch: the successful items only answered, so neither a change
            // nor a save is claimed.
            Self::Nothing => (keys::WEB_EXPLORER_PARTIAL_ANSWERED, "partially_failed"),
        };
        (tr(locale, key, Some(&args)), audit)
    }
}

/// The reply of the explorer or a console to one request.
pub(crate) struct Reply {
    /// Headline, problems, the router's own words, toast and unsaved badge.
    outcome: Outcome,
    /// The router's answer.
    viewer: Option<Viewer>,
    /// Download link of an answer too large for the page.
    download: Option<String>,
    /// A started background command.
    job: Option<JobPanel>,
    /// Stable persistence state marker for UI automation.
    persistence: &'static str,
}

/// The reply fragment.
#[derive(Template)]
#[template(path = "partials/explorer_outcome.html")]
struct ReplyView {
    /// Locale carrier.
    shell: Shell,
    /// The reply.
    reply: Reply,
}

impl Localize for ReplyView {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Reply {
    /// A reply showing `outcome` and nothing else.
    const fn of(outcome: Outcome) -> Self {
        Self {
            outcome,
            viewer: None,
            download: None,
            job: None,
            persistence: "none",
        }
    }

    /// A request that was not sent because of `problems`.
    pub(crate) fn invalid(locale: Locale, problems: &[Problem]) -> Self {
        let sentences = problems
            .iter()
            .map(|problem| sentence(locale, problem))
            .collect();
        Self::of(Outcome::invalid(Family::Commands, locale, sentences))
    }

    /// A request the router or the workflow refused.
    pub(crate) fn failed(failure: Failure) -> Self {
        Self::of(Outcome::failed(failure))
    }

    /// A batch that applied some items and refused others.
    pub(crate) fn partial(
        headline: String,
        router_said: Vec<String>,
        viewer: Viewer,
        left: &Left,
        audit: &'static str,
    ) -> Self {
        let unsaved = matches!(left, Left::Unsaved | Left::Mixed(_));
        let persistence = match left {
            Left::Nothing | Left::Unsaved => "none",
            Left::Stored => "stored",
            Left::Mixed(_) => "mixed",
        };
        Self {
            outcome: Outcome::partial(headline, router_said, unsaved, audit),
            viewer: Some(viewer),
            download: None,
            job: None,
            persistence,
        }
    }

    /// A completed command and the router's answer.
    pub(crate) fn done(locale: Locale, viewer: Viewer, left: Left) -> Self {
        let persistence = match &left {
            Left::Nothing | Left::Unsaved => "none",
            Left::Stored => "stored",
            Left::Mixed(_) => "mixed",
        };
        let (key, unsaved) = match left {
            Left::Nothing => (Family::Commands.done(false), false),
            Left::Unsaved => (Family::Commands.done(true), true),
            Left::Stored => (keys::WEB_EXPLORER_DONE_PERSISTED, false),
            Left::Mixed(paths) => {
                let mut args = fluent_bundle::FluentArgs::new();
                args.set("paths", paths.join(", "));
                let headline = tr(locale, keys::WEB_EXPLORER_MIXED_PERSISTENCE, Some(&args));
                return Self {
                    viewer: Some(viewer),
                    persistence: "mixed",
                    ..Self::of(Outcome::done(headline, true))
                };
            }
        };
        let headline = tr(locale, key, None);
        Self {
            viewer: Some(viewer),
            persistence,
            ..Self::of(Outcome::done(headline, unsaved))
        }
    }

    /// A started background command.
    pub(crate) fn job(locale: Locale, panel: JobPanel) -> Self {
        let headline = tr(locale, keys::WEB_EXPLORER_JOB_STARTED, None);
        Self {
            job: Some(panel),
            ..Self::of(Outcome::info(headline, "started"))
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

    /// The outcome, as the audit records it.
    pub(crate) const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The reply fragment in `locale`.
    pub(crate) fn render(self, locale: Locale) -> Response {
        let status = self.outcome.status();
        let view = ReplyView {
            shell: fragment_shell(locale),
            reply: self,
        };
        with_status(errors::render(&view), status)
    }
}
