//! `POST /ui/admin/mcp/ca`: a client CA or the identity provider's CA bundle.
//!
//! The PEM file of at most 64 KiB is stored below the state directory. Only the size and
//! the PEM shape are checked here; the listeners check the certificates when they use
//! them. The upload takes no path and nothing of the file reaches a page or the log.

use axum::{
    body::Bytes,
    extract::{
        Multipart, State,
        multipart::{MultipartError, MultipartRejection},
    },
    http::StatusCode,
    response::Response,
};
use kcc_app::persist::{create_private_dir, write_atomic};
use kcc_i18n::keys;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{
    flow::audit,
    messages::Said,
    page::{DIRECTORY, MTLS_CA, OIDC_CA},
    pem, reply,
};
use crate::{
    WebState, admin_shared::unavailable, authz::CurrentUser, errors,
    page_kit::context::fragment_shell,
};

/// The largest CA file.
pub(crate) const FILE_LIMIT: usize = 64 * 1024;

/// The largest upload request: the file and its multipart framing.
pub(crate) const BODY_LIMIT: usize = FILE_LIMIT.saturating_add(0x4000);

/// Why an upload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A field besides `kind` and `file`, an unknown kind, or a missing one.
    Fields,
    /// The file is larger than [`FILE_LIMIT`].
    TooLarge,
    /// The file is not PEM certificates only.
    NotPem,
}

/// `POST /ui/admin/mcp/ca`: stores the file as the kind's CA.
// NOT cancel-safe: the file is written on a blocking thread that finishes even if the future is
// dropped, leaving the upload unaudited.
pub(crate) async fn upload(
    State(state): State<WebState>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let (Some(admin), Some(_attached)) = (state.admin(), state.mcp()) else {
        return unavailable(None);
    };
    let locale = user.locale();
    let read = match multipart {
        Ok(fields) => read(fields).await,
        Err(_rejection) => Err(Refusal::Fields),
    };
    let (name, bytes) = match read.and_then(checked) {
        Ok(upload) => upload,
        Err(refusal) => {
            let key = match refusal {
                Refusal::Fields => keys::WEB_ADMIN_MCP_ERROR_UPLOAD_FIELDS,
                Refusal::TooLarge => keys::WEB_ADMIN_MCP_ERROR_UPLOAD_SIZE,
                Refusal::NotPem => keys::WEB_ADMIN_MCP_ERROR_UPLOAD_PEM,
            };
            let said = Said::new(locale, key, None);
            return reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    let _changes = admin.lock().await;
    let dir = admin.state().dir().join(DIRECTORY);
    let written = spawn_blocking(move || {
        create_private_dir(&dir)?;
        write_atomic(&dir, name, &bytes)
    })
    .await;
    match written {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(locale)),
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    }
    let key = if name == MTLS_CA {
        "auth.mtls.ca"
    } else {
        "auth.oidc.ca"
    };
    let params = json!({ "changed": [key], "restarted": [] });
    audit(&state, &user, params, "success").await;
    let said = Said::new(locale, keys::WEB_ADMIN_MCP_CA_SAVED, None);
    reply::notice(&state, locale, (said, "success"), StatusCode::OK).await
}

/// The kind and the file of the upload; any other field refuses it.
///
/// # Errors
///
/// [`Refusal::Fields`] for another, missing or unreadable field, [`Refusal::TooLarge`]
/// past the body limit.
// cancel-safe: reads the request body only.
async fn read(mut fields: Multipart) -> Result<(String, Bytes), Refusal> {
    let (mut kind, mut file) = (None, None);
    while let Some(field) = fields.next_field().await.map_err(|error| unread(&error))? {
        match field.name() {
            Some("kind") if kind.is_none() => {
                kind = Some(field.text().await.map_err(|error| unread(&error))?);
            }
            Some("file") if file.is_none() => {
                file = Some(field.bytes().await.map_err(|error| unread(&error))?);
            }
            Some(_) | None => return Err(Refusal::Fields),
        }
    }
    kind.zip(file).ok_or(Refusal::Fields)
}

/// The file name the kind is stored as, once the file passed the size and shape checks.
///
/// # Errors
///
/// [`Refusal::Fields`] for an unknown kind, [`Refusal::TooLarge`] or
/// [`Refusal::NotPem`] for the file.
fn checked((kind, bytes): (String, Bytes)) -> Result<(&'static str, Bytes), Refusal> {
    let name = match kind.as_str() {
        "mtls" => MTLS_CA,
        "oidc" => OIDC_CA,
        _ => return Err(Refusal::Fields),
    };
    if bytes.len() > FILE_LIMIT {
        return Err(Refusal::TooLarge);
    }
    if pem::certificates(&bytes).is_none() {
        return Err(Refusal::NotPem);
    }
    Ok((name, bytes))
}

/// Why reading a multipart field failed.
fn unread(error: &MultipartError) -> Refusal {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Refusal::TooLarge
    } else {
        Refusal::Fields
    }
}
