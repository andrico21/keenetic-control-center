//! `GET /ui/r/{router}/config/backups/download?name=[&full=yes]`: one backup as a file.
//!
//! As stored, with its secrets, only for `RevealSecrets` (`full=yes`); otherwise the copy
//! without them: every registered secret and every `ns3` blob replaced, the stale
//! checksum dropped, the copy marked so that it is never stored back. Audited either way,
//! with the variant and never a value.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_config::mask::redacted_copy;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::json;

use super::store::{self, DOWNLOAD, DOWNLOAD_FULL, StoreError};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::respond::{Answer, attachment},
};

/// The download a request asks for.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    /// The backup's file name.
    name: String,
    /// `yes` for the backup with its secrets.
    #[serde(default)]
    full: Option<String>,
}

/// `GET /ui/r/{router}/config/backups/download`: the backup as a text file.
///
/// # Errors
///
/// Answers 404 for an unknown backup, 500 when it cannot be read, and 404, 503 or the
/// audited 403 when the router, the store or the permission is missing.
// NOT cancel-safe: the download's audit entry may be written after the future is dropped.
pub(crate) async fn download(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(wanted): Query<Wanted>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let full = wanted.full.as_deref() == Some("yes");
    let act = if full { DOWNLOAD_FULL } else { DOWNLOAD };
    let opened = act.open(&state, &user, &router).await?;
    let variant = json!({ "variant": if full { "full" } else { "redacted" } });
    let stored = match store::read(opened.services(), &router, &wanted.name).await {
        Ok(found) => found,
        Err(error) => {
            let (status, audit) = match error {
                StoreError::Missing => (StatusCode::NOT_FOUND, "not_found"),
                StoreError::Failed => (StatusCode::INTERNAL_SERVER_ERROR, "failed"),
            };
            opened.finish((&wanted.name, variant), audit).await;
            return Err(status.into_response().into());
        }
    };
    let body = if full {
        stored.expose_secret().to_owned()
    } else if let Ok(copy) = redacted_copy(stored.expose_secret()) {
        copy
    } else {
        opened.finish((&wanted.name, variant), "unreadable").await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response().into());
    };
    opened.finish((&wanted.name, variant), "success").await;
    let stem = wanted.name.strip_suffix(".txt").unwrap_or(&wanted.name);
    let file = if full {
        format!("{router}-{stem}.txt")
    } else {
        format!("{router}-{stem}-redacted.txt")
    };
    Ok(attachment(body, "text/plain; charset=utf-8", &file))
}
