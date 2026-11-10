//! What a request shows when it is done.
//!
//! A headline in its tone, the problems that stopped it, the router's own words when it
//! refused (message text only, never a request body), and, out of band, the toasts and
//! the header's unsaved badge.

use askama::Template;
use axum::{http::StatusCode, response::Response};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{context::fragment_shell, family::Family};
use crate::{
    errors,
    page::{Localize, Shell},
};

#[cfg(test)]
mod notice_tone_tests;

/// The tone of a notice or a toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Done as asked.
    Success,
    /// Under way, or nothing to report.
    Info,
    /// Done, with something to look at.
    Warning,
    /// Not done.
    Error,
}

impl Tone {
    /// The `data-tone` value.
    pub(crate) const fn value(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A toast sent along with a response, out of band into `#toasts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Toast {
    /// The toast tone.
    tone: Tone,
    /// The localized message.
    message: String,
}

impl Toast {
    /// A toast with an already localized `message`.
    pub(crate) const fn new(tone: Tone, message: String) -> Self {
        Self { tone, message }
    }

    /// A success toast with `key` in `locale`.
    pub(crate) fn success(locale: Locale, key: MessageKey) -> Self {
        Self::new(Tone::Success, tr(locale, key, None))
    }

    /// A warning toast with `key` in `locale`.
    pub(crate) fn warning(locale: Locale, key: MessageKey) -> Self {
        Self::new(Tone::Warning, tr(locale, key, None))
    }

    /// An error toast with `key` in `locale`.
    pub(crate) fn error(locale: Locale, key: MessageKey) -> Self {
        Self::new(Tone::Error, tr(locale, key, None))
    }

    /// The toast tone.
    pub(crate) const fn tone(&self) -> &'static str {
        self.tone.value()
    }

    /// The localized message.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// Why a request failed, in the user's words.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    /// Localized explanation.
    message: String,
    /// The router's own status messages: message text only.
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

    /// Stable audit outcome id.
    pub(crate) const fn audit(&self) -> &'static str {
        self.audit
    }
}

/// The outcome of one request.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// Notice tone.
    tone: Tone,
    /// The localized headline.
    headline: String,
    /// Why the request was not sent, one sentence each.
    problems: Vec<String>,
    /// The router's own status messages when it refused.
    router_said: Vec<String>,
    /// Toasts sent along.
    toasts: Vec<Toast>,
    /// Whether the router now has unsaved changes, which shows the header badge.
    unsaved: bool,
    /// HTTP status: 422 for a request that was not sent.
    status: StatusCode,
    /// Stable audit outcome id.
    audit: &'static str,
}

/// The outcome fragment of a page's outcome region.
#[derive(Template)]
#[template(path = "partials/kit_outcome.html")]
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

impl Outcome {
    /// An outcome in `tone` with `headline`, audited as `audit`, and nothing else.
    const fn base(tone: Tone, headline: String, audit: &'static str) -> Self {
        Self {
            tone,
            headline,
            problems: Vec::new(),
            router_said: Vec::new(),
            toasts: Vec::new(),
            unsaved: false,
            status: StatusCode::OK,
            audit,
        }
    }

    /// A request stopped before anything was sent: `problems` say why, as 422.
    pub(crate) fn invalid(family: Family, locale: Locale, problems: Vec<String>) -> Self {
        Self {
            problems,
            status: StatusCode::UNPROCESSABLE_ENTITY,
            ..Self::base(
                Tone::Error,
                tr(locale, family.invalid(), None),
                "validation_failed",
            )
        }
    }

    /// A request the router or the change workflow refused; the request itself worked.
    pub(crate) fn failed(failure: Failure) -> Self {
        Self {
            router_said: failure.router_said,
            ..Self::base(Tone::Error, failure.message, failure.audit)
        }
    }

    /// A completed request: `headline`, also sent as a success toast, and whether the
    /// router now has unsaved changes.
    pub(crate) fn done(headline: String, unsaved: bool) -> Self {
        Self {
            toasts: vec![Toast::new(Tone::Success, headline.clone())],
            unsaved,
            ..Self::base(Tone::Success, headline, "success")
        }
    }

    /// A partly completed request with a truthful persistence notice and audit outcome.
    pub(crate) fn partial(
        headline: String,
        router_said: Vec<String>,
        unsaved: bool,
        audit: &'static str,
    ) -> Self {
        Self {
            router_said,
            unsaved,
            ..Self::base(Tone::Warning, headline, audit)
        }
    }

    /// A request under way, such as a started job, audited as `audit`.
    pub(crate) const fn info(headline: String, audit: &'static str) -> Self {
        Self::base(Tone::Info, headline, audit)
    }

    /// Notice tone.
    pub(crate) const fn tone(&self) -> &'static str {
        self.tone.value()
    }

    /// Whether the request did what it was asked to.
    pub(crate) const fn succeeded(&self) -> bool {
        matches!(self.tone, Tone::Success)
    }

    /// The localized headline.
    pub(crate) fn headline(&self) -> &str {
        &self.headline
    }

    /// Why the request was not sent.
    pub(crate) fn problems(&self) -> &[String] {
        &self.problems
    }

    /// The router's own words.
    pub(crate) fn router_said(&self) -> &[String] {
        &self.router_said
    }

    /// Toasts sent along.
    pub(crate) fn toasts(&self) -> &[Toast] {
        &self.toasts
    }

    /// Whether the router now has unsaved changes.
    pub(crate) const fn unsaved(&self) -> bool {
        self.unsaved
    }

    /// HTTP status of the answer.
    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    /// Stable audit outcome id.
    pub(crate) const fn audit(&self) -> &'static str {
        self.audit
    }

    /// The outcome fragment in `locale`, for a page's outcome region (`#page-outcome`).
    pub(crate) fn render(self, locale: Locale) -> Response {
        let status = self.status;
        let view = OutcomeView {
            shell: fragment_shell(locale),
            outcome: self,
        };
        with_status(errors::render(&view), status)
    }
}

/// `response` with `status`, unless rendering it already failed.
pub(crate) fn with_status(mut response: Response, status: StatusCode) -> Response {
    if response.status() == StatusCode::OK {
        *response.status_mut() = status;
    }
    response
}
