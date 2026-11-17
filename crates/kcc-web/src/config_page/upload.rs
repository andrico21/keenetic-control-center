//! A startup-configuration file stored as a backup: a multipart upload of at most 1 MiB
//! that must be a router configuration.
//!
//! The file must be text, parse as a configuration with at least one command, and match
//! its own checksum header when it has one; a copy kcc redacted is refused, since storing
//! it would make a backup without secrets. The text goes straight into a secret buffer and
//! from there into the encrypted store; nothing from the file reaches a page or the log.

use core::str;

use askama::Template;
use axum::{
    body::Bytes,
    extract::{
        Multipart, Path, Request, State,
        multipart::{MultipartError, MultipartRejection},
    },
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::json;

use super::{
    page::Visit,
    store::{self, StoreError, UPLOAD},
    upload_check::{FILE_LIMIT, Refusal, checked},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, outcome::Outcome, respond, respond::Answer},
};

/// Room for the multipart framing around the file.
const FRAMING: usize = 0x4000;

/// Largest upload request: the file and its framing.
pub(crate) const BODY_LIMIT: usize = FILE_LIMIT.saturating_add(FRAMING);

/// The upload dialog.
#[derive(Template)]
#[template(path = "partials/config_upload.html")]
struct UploadDialog {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The error under the file field, empty when none.
    error: String,
}

localized!(UploadDialog);

/// `GET /ui/r/{router}/config/upload`: the upload dialog.
///
/// # Errors
///
/// Answers 404, 503 or the audited 403 when the router, the store or the permission is
/// missing.
// NOT cancel-safe: a refusal queues an audit entry that may be written after the future is dropped;
// otherwise it only reads.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let _opened = UPLOAD.open(&state, &user, &router).await?;
    Ok(shown(&router, user.locale(), String::new(), StatusCode::OK))
}

/// `POST /ui/r/{router}/config/backups/upload`: stores the file as a backup.
///
/// # Errors
///
/// Answers the dialog with the file's error (422, or 413 when too large), and 404, 503
/// or the audited 403 when the router, the store or the permission is missing.
// NOT cancel-safe: the uploaded backup may be stored, and its audit entry queued, after the future
// is dropped.
pub(crate) async fn upload(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, Answer> {
    let opened = UPLOAD.open(&state, &user, &router).await?;
    let locale = user.locale();
    let read = match multipart {
        Ok(fields) => file(fields).await,
        Err(_rejection) => Err(Refusal::NotText),
    };
    let (reason, text) = match read.and_then(|(name, bytes)| checked(name.as_deref(), &bytes)) {
        Ok(ready) => ready,
        Err(refusal) => {
            let (status, message, audit) = refusal.describe(locale);
            let answer = shown(&router, locale, message, status);
            return Err(opened.refuse("upload", audit, answer).await);
        }
    };
    let fields = json!({ "fields": ["file"] });
    match store::keep(opened.services(), &router, (reason, text)).await {
        Ok(info) => {
            let visit = Visit::new(&state, &user, &router);
            opened.finish((&info.name, fields), "success").await;
            let outcome = Outcome::done(tr(locale, keys::WEB_CONFIG_BACKUP_STORED, None), false);
            Ok(visit.answer_backups(outcome, &headers).await)
        }
        Err(StoreError::Missing | StoreError::Failed) => {
            let message = tr(locale, keys::WEB_CONFIG_STORE_FAILED, None);
            let answer = shown(&router, locale, message, StatusCode::CONFLICT);
            Err(opened.refuse("upload", "failed", answer).await)
        }
    }
}

/// Answers a request the body limit stopped (413 with no dialog) with the upload dialog
/// and its localized size error.
// NOT cancel-safe: it awaits the rest of the request, whose handler may change the router or local
// state, or queue an audit entry, before the future is dropped.
pub(crate) async fn limit(request: Request, next: Next) -> Response {
    let locale = request
        .extensions()
        .get::<CurrentUser>()
        .map(CurrentUser::locale);
    let router = request
        .uri()
        .path()
        .strip_prefix("/ui/r/")
        .and_then(|rest| rest.split('/').next())
        .map(str::to_owned);
    let response = next.run(request).await;
    let bare = response.status() == StatusCode::PAYLOAD_TOO_LARGE
        && !response.headers().contains_key("hx-retarget");
    match (bare, locale, router) {
        (true, Some(found), Some(id)) => {
            let (status, message, _audit) = Refusal::TooLarge.describe(found);
            shown(&id, found, message, status)
        }
        (_, _, _) => response,
    }
}

/// The upload dialog on `router` with `error` under the file field, as `status`.
fn shown(router: &str, locale: Locale, error: String, status: StatusCode) -> Response {
    let mut response = errors::render(&UploadDialog {
        shell: fragment_shell(locale),
        router: router.to_owned(),
        error,
    });
    if response.status() == StatusCode::OK {
        *response.status_mut() = status;
    }
    respond::in_dialog(response)
}

/// The uploaded file's name and bytes; other fields are ignored.
///
/// # Errors
///
/// Returns why the upload could not be read.
// cancel-safe: reads the request body only.
async fn file(mut fields: Multipart) -> Result<(Option<String>, Bytes), Refusal> {
    let mut found = (None, Bytes::new());
    while let Some(field) = fields.next_field().await.map_err(|error| unread(&error))? {
        if field.name() == Some("file") {
            let name = field.file_name().map(str::to_owned);
            found = (name, field.bytes().await.map_err(|error| unread(&error))?);
        }
    }
    Ok(found)
}

/// Why reading a multipart field failed.
fn unread(error: &MultipartError) -> Refusal {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Refusal::TooLarge
    } else {
        Refusal::NotText
    }
}
