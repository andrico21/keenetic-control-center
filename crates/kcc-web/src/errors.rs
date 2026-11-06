//! Generic, localized error pages: 404, 403 and 500.
//!
//! An error page names the failure in the visitor's language and links back to the
//! dashboard. It never shows the request path, an error message, a stack trace or any
//! other internal detail; the cause of a 500 goes to the server log instead.

use core::fmt::Display;

use askama::Template;
use axum::{
    http::{StatusCode, header},
    response::{Html, IntoResponse as _, Response},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use crate::page::{Localize, Shell};

/// The error pages of the Web UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// No page exists at the requested path (404).
    NotFound,
    /// The signed-in user lacks the permission the page needs (403).
    Forbidden,
    /// The request failed on the server (500).
    Internal,
}

impl Kind {
    /// The HTTP status of the page.
    #[inline]
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The page heading and title.
    #[inline]
    #[must_use]
    pub const fn title(self) -> MessageKey {
        match self {
            Self::NotFound => keys::WEB_ERROR_NOT_FOUND_TITLE,
            Self::Forbidden => keys::WEB_ERROR_FORBIDDEN_TITLE,
            Self::Internal => keys::WEB_ERROR_INTERNAL_TITLE,
        }
    }

    /// The sentence under the heading.
    #[inline]
    #[must_use]
    pub const fn text(self) -> MessageKey {
        match self {
            Self::NotFound => keys::WEB_ERROR_NOT_FOUND_TEXT,
            Self::Forbidden => keys::ERRORS_FORBIDDEN,
            Self::Internal => keys::WEB_ERROR_INTERNAL_TEXT,
        }
    }
}

/// The error page template.
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    /// Page shell in the visitor's locale and theme.
    shell: Shell,
    /// Which error the page reports.
    kind: Kind,
}

impl Localize for ErrorPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The error page for `kind`, rendered inside `shell`, with `kind`'s status code.
///
/// Should the template itself fail, the response is the localized title as plain text.
#[inline]
#[must_use]
pub fn response(kind: Kind, shell: Shell) -> Response {
    let locale = shell.locale();
    match (ErrorPage { shell, kind }).render() {
        Ok(html) => (kind.status(), Html(html)).into_response(),
        Err(error) => {
            tracing::error!(%error, "error page template failed to render");
            (
                kind.status(),
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                tr(locale, kind.title(), None),
            )
                .into_response()
        }
    }
}

/// Renders a page template with status 200; a template failure is logged and answered
/// with the 500 page.
pub(crate) fn render<T>(page: &T) -> Response
where
    T: Template + Localize,
{
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "page template failed to render");
            let shell = page.shell();
            response(Kind::Internal, Shell::new(shell.locale(), shell.theme()))
        }
    }
}

/// Logs `error` as the cause of a failed request and answers with the 500 page.
pub(crate) fn internal<E>(error: &E, shell: Shell) -> Response
where
    E: Display + ?Sized,
{
    tracing::error!(%error, "web request failed");
    response(Kind::Internal, shell)
}
