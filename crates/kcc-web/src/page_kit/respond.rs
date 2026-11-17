//! The htmx answers pages share: sending the browser elsewhere, choosing where a fragment
//! lands, opening or closing the shared dialog, and the answer to a change.

use askama::Template;
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kcc_i18n::{keys, locale::Locale};

use super::{
    context::fragment_shell,
    outcome::{Outcome, with_status},
};
use crate::{
    errors,
    page::{Localize, Shell},
};

#[cfg(test)]
mod changed_tests;

/// The response a handler answers with instead of going on: a refusal, a dialog with its
/// field errors, an outcome. Handlers return `Result<Response, Answer>` and use `?`.
pub(crate) struct Answer(Box<Response>);

impl From<Response> for Answer {
    fn from(response: Response) -> Self {
        Self(Box::new(response))
    }
}

impl IntoResponse for Answer {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// Answers an htmx form post by sending the browser to `href`.
pub(crate) fn open(href: &str) -> Response {
    let mut response = StatusCode::OK.into_response();
    match HeaderValue::from_str(href) {
        Ok(value) => drop(response.headers_mut().insert("hx-redirect", value)),
        Err(error) => tracing::error!(%error, "redirect target is not a header value"),
    }
    response
}

/// Shows `response` in `target` instead of the requesting element's own target, such as
/// a console's live check region, which already holds the same kind of finding.
pub(crate) fn retarget(mut response: Response, target: &'static str) -> Response {
    drop(
        response
            .headers_mut()
            .insert("hx-retarget", HeaderValue::from_static(target)),
    );
    response
}

/// Shows a rendered dialog body in the shared `<dialog>`, whatever the request targeted;
/// a failed render keeps its own target.
pub(crate) fn in_dialog(mut response: Response) -> Response {
    if !response.status().is_server_error() {
        let headers = response.headers_mut();
        drop(headers.insert("hx-retarget", HeaderValue::from_static("#dialog-content")));
        drop(headers.insert("hx-reswap", HeaderValue::from_static("innerHTML")));
    }
    response
}

/// Marks `response` to close the shared dialog when it arrives.
pub(crate) fn close_dialog(mut response: Response) -> Response {
    drop(
        response
            .headers_mut()
            .insert("hx-trigger", HeaderValue::from_static("kcc:dialog-close")),
    );
    response
}

/// `body` as `content_type`, downloaded as a file named `name`.
pub(crate) fn attachment(body: String, content_type: &'static str, name: &str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    drop(headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type)));
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        drop(headers.insert(header::CONTENT_DISPOSITION, value));
    }
    response
}

/// A form or dialog shown again with its field errors, as 422.
pub(crate) fn unprocessable<T>(page: &T) -> Response
where
    T: Template + Localize,
{
    let mut response = errors::render(page);
    *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    response
}

/// Answers a change made from a table with `region`, which carries the table and its
/// toasts out of band, and `status`. A change made from the dialog closes it and leaves
/// its content unswapped.
pub(crate) fn region<T>(region: &T, status: StatusCode, from_dialog: bool) -> Response
where
    T: Template + Localize,
{
    let mut response = errors::render(region);
    *response.status_mut() = status;
    if from_dialog {
        let headers = response.headers_mut();
        drop(headers.insert("hx-reswap", HeaderValue::from_static("none")));
        drop(headers.insert(
            "hx-trigger-after-swap",
            HeaderValue::from_static("kcc:dialog-close"),
        ));
    }
    response
}

/// The answer to a change, for the page's outcome region: the outcome, then what the page
/// says beyond it, then the page's region read back, out of band.
#[derive(Template)]
#[template(path = "partials/kit_result.html")]
pub(crate) struct Changed {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
    /// The page's own report of what the change did, shown in place of the outcome's
    /// notice.
    report: Option<String>,
    /// What the page says beyond the outcome, rendered.
    extra: Option<String>,
    /// The region read back, rendered for sending out of band.
    refreshed: Option<String>,
}

localized!(Changed);

impl Changed {
    /// The answer showing `outcome` in `locale`, then `extra`, then `refreshed`.
    pub(crate) const fn new(
        outcome: Outcome,
        refreshed: Option<String>,
        extra: Option<String>,
        locale: Locale,
    ) -> Self {
        Self {
            shell: fragment_shell(locale),
            outcome,
            report: None,
            extra,
            refreshed,
        }
    }

    /// Shows `report` in place of the outcome's notice; the outcome's toasts and the
    /// unsaved badge still go out of band.
    pub(crate) fn with_report(mut self, report: String) -> Self {
        self.report = Some(report);
        self
    }

    /// HTTP status of the answer: the outcome's.
    pub(crate) const fn status(&self) -> StatusCode {
        self.outcome.status()
    }
}

/// The answer to a change: `outcome` in the page's outcome region with `extra` after it,
/// the `refreshed` region out of band, the shared dialog closed.
pub(crate) fn changed(
    outcome: Outcome,
    refreshed: Option<String>,
    extra: Option<String>,
    locale: Locale,
) -> Response {
    let view = Changed::new(outcome, refreshed, extra, locale);
    close_dialog(with_status(errors::render(&view), view.status()))
}
