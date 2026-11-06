//! The htmx answers pages share: sending the browser elsewhere, choosing where a fragment
//! lands, and opening or closing the shared dialog.

use askama::Template;
use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{errors, page::Localize};

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
