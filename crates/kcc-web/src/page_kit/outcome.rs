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
use notice::{OutcomeView, Tone};

use super::{context::fragment_shell, failure::FailureKind, family::Family, submit::work::Report};
use crate::{
    errors,
    page::{Localize as _, Shell},
};

mod notice;
#[cfg(test)]
mod notice_tone_tests;

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

    /// An info toast with `key` in `locale`.
    pub(crate) fn info(locale: Locale, key: MessageKey) -> Self {
        Self::new(Tone::Info, tr(locale, key, None))
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

/// A template wrapper for rendering a toast.
#[derive(Template)]
#[template(
    ext = "html",
    source = "{%- import \"components.html\" as ui -%}{{ ui::toast(tone, message) }}"
)]
pub(crate) struct ToastView {
    /// Locale carrier.
    shell: Shell,
    /// Toast tone.
    tone: &'static str,
    /// Localized message.
    message: String,
}

impl ToastView {
    /// Create a `ToastView` from a `Toast` in the given `locale`.
    pub(crate) fn new(toast: &Toast, locale: Locale) -> Self {
        Self {
            shell: fragment_shell(locale),
            tone: toast.tone(),
            message: toast.message().to_owned(),
        }
    }
}

localized!(ToastView);

/// Why a request failed, in the user's words.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    /// What the failure says about the request.
    kind: FailureKind,
    /// Localized explanation.
    message: String,
    /// The router's own status messages: message text only.
    router_said: Vec<String>,
    /// Stable audit outcome id.
    audit: &'static str,
    /// Whether the recovery timer may still be armed.
    fail_safe_armed: bool,
}

impl Failure {
    /// A failure explained by `message`, audited as `audit`.
    pub(crate) const fn new(message: String, audit: &'static str) -> Self {
        Self {
            kind: FailureKind::Failed,
            message,
            router_said: Vec::new(),
            audit,
            fail_safe_armed: false,
        }
    }

    /// The refusal of a change the role may not make, audited `forbidden`.
    pub(crate) fn forbidden(locale: Locale) -> Self {
        Self {
            kind: FailureKind::Forbidden,
            ..Self::new(tr(locale, keys::ERRORS_FORBIDDEN, None), "forbidden")
        }
    }

    /// Whether the role may not make the change.
    pub(crate) const fn is_forbidden(&self) -> bool {
        matches!(self.kind, FailureKind::Forbidden)
    }

    /// The failure of a change that may have left the recovery timer armed.
    pub(crate) const fn with_fail_safe_armed(mut self) -> Self {
        self.fail_safe_armed = true;
        self
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
    /// Whether a failed change may have left the recovery timer armed.
    fail_safe_armed: bool,
    /// Whether the change's audit entries are still queued behind another process's
    /// append lock.
    audit_pending: bool,
    /// What the page's work said beyond the outcome.
    report: Option<Report>,
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
            fail_safe_armed: false,
            audit_pending: false,
            report: None,
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
            fail_safe_armed: failure.fail_safe_armed,
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

    /// The same completed request whose audit entries are still queued: its toast says
    /// they are written once the audit log is free.
    pub(crate) fn with_audit_pending(self, locale: Locale) -> Self {
        Self {
            toasts: vec![Toast::new(
                Tone::Success,
                tr(locale, keys::AUDIT_ENTRY_PENDING, None),
            )],
            audit_pending: true,
            ..self
        }
    }

    /// The same outcome with `report`, what the page's work said beyond it.
    pub(crate) fn with_report(self, report: Option<Report>) -> Self {
        Self { report, ..self }
    }

    /// What the page's work said beyond the outcome, taken out of it.
    pub(crate) const fn take_report(&mut self) -> Option<Report> {
        self.report.take()
    }

    /// The same outcome, saying whether the router now has unsaved changes, such as after
    /// a restore that ran when the change itself failed.
    pub(crate) const fn with_unsaved(mut self, unsaved: bool) -> Self {
        self.unsaved = unsaved;
        self
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

    /// Whether a failed change may have left the recovery timer armed.
    pub(crate) const fn fail_safe_armed(&self) -> bool {
        self.fail_safe_armed
    }

    /// Whether the change's audit entries are still queued.
    pub(crate) const fn audit_pending(&self) -> bool {
        self.audit_pending
    }

    /// The outcome fragment in `locale`, for a page's outcome region (`#page-outcome`).
    pub(crate) fn render(self, locale: Locale) -> Response {
        let status = self.status;
        with_status(errors::render(&OutcomeView::new(locale, self)), status)
    }
}

/// `response` with `status`, unless rendering it already failed.
pub(crate) fn with_status(mut response: Response, status: StatusCode) -> Response {
    if response.status() == StatusCode::OK {
        *response.status_mut() = status;
    }
    response
}
