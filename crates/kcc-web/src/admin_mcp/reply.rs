//! The page's answers: a notice or the restart status with the region read again, and
//! the password dialog.

use askama::Template;
use axum::{http::StatusCode, response::Response};
use kcc_i18n::{keys, locale::Locale};

use super::{messages::Said, page::fresh, status::Status, view::Region};
use crate::{
    WebState, errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, respond},
};

/// The answer to a change, for `#page-outcome`.
#[derive(Template)]
#[template(path = "partials/admin_mcp_answer.html")]
struct Answer {
    /// Locale carrier.
    shell: Shell,
    /// The notice, if any.
    notice: Option<Said>,
    /// The notice's tone.
    tone: &'static str,
    /// The restart status, if a restart runs.
    status: Option<Status>,
    /// The region read again, out of band.
    region: Option<Region>,
}

localized!(Answer);

/// The password dialog.
#[derive(Template)]
#[template(path = "partials/admin_mcp_confirm.html")]
struct Confirm {
    /// Locale carrier.
    shell: Shell,
    /// What the change reduces.
    text: String,
    /// Why the last attempt was refused, if it was.
    refusal: Option<Said>,
    /// Where the form posts.
    post_to: &'static str,
    /// The change's fields, without the password.
    pairs: Vec<(String, String)>,
}

localized!(Confirm);

/// `said` in `tone` with the region read again, as `status`.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn notice(
    state: &WebState,
    locale: Locale,
    (said, tone): (Said, &'static str),
    status: StatusCode,
) -> Response {
    answer(state, locale, (Some(said), tone), None, status).await
}

/// The restart `progress` with the region read again.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn restarting(state: &WebState, locale: Locale, progress: Status) -> Response {
    answer(
        state,
        locale,
        (None, "info"),
        Some(progress),
        StatusCode::OK,
    )
    .await
}

/// The answer of `notice` and `progress`, as `status`.
// cancel-safe: it only reads local state on a blocking thread.
async fn answer(
    state: &WebState,
    locale: Locale,
    (notice, tone): (Option<Said>, &'static str),
    progress: Option<Status>,
    status: StatusCode,
) -> Response {
    let region = match fresh(state, locale).await {
        Ok(region) => Some(region),
        Err(error) => {
            tracing::error!(%error, "MCP settings region could not be read again");
            None
        }
    };
    let mut response = errors::render(&Answer {
        shell: fragment_shell(locale),
        notice,
        tone,
        status: progress,
        region,
    });
    if response.status().is_success() {
        *response.status_mut() = status;
    }
    response
}

/// A refusal of the form itself, as 422 in `#page-outcome`.
pub(crate) fn refused(locale: Locale, said: Said, status: StatusCode) -> Response {
    let mut response = errors::render(&Answer {
        shell: fragment_shell(locale),
        notice: Some(said),
        tone: "error",
        status: None,
        region: None,
    });
    if response.status().is_success() {
        *response.status_mut() = status;
    }
    response
}

/// The password dialog for a change posted to `post_to` as `pairs`, saying what it
/// reduces (`text`) and, after a refused attempt, why (`refusal`).
pub(crate) fn dialog(
    locale: Locale,
    (post_to, pairs): (&'static str, &[(String, String)]),
    text: String,
    refusal: Option<Said>,
) -> Response {
    let status = if refusal.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let mut response = errors::render(&Confirm {
        shell: fragment_shell(locale),
        text,
        refusal,
        post_to,
        pairs: pairs
            .iter()
            .filter(|(name, _)| name != "password")
            .cloned()
            .collect(),
    });
    if response.status().is_success() {
        *response.status_mut() = status;
    }
    respond::in_dialog(response)
}
