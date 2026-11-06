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

    /// A completed command and the router's answer.
    pub(crate) fn done(locale: Locale, viewer: Viewer, unsaved: bool) -> Self {
        let headline = tr(locale, Family::Commands.done(unsaved), None);
        Self {
            viewer: Some(viewer),
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

    /// Stable audit outcome id.
    pub(crate) const fn audit(&self) -> &'static str {
        self.outcome.audit()
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
