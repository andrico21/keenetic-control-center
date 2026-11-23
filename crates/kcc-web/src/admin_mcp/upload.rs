//! `POST /ui/admin/mcp/ca`: the client CA or the identity provider's CA bundle.
//!
//! The file of at most 64 KiB is checked here: the identity provider's bundle for its PEM
//! shape (it is stored at once), the client CA as the client-certificate sign-in takes it
//! (one to ten CA certificates). The client CA goes to the running listeners, which store
//! it in their serialized section; while a listener uses client certificates, replacing it
//! reduces safety (it changes who may sign in), so the form carries the account's password
//! and the listeners using it restart, polled like a settings restart. The upload takes no
//! path and nothing of the file reaches a page or the log.

extern crate alloc;

use alloc::sync::Arc;

use axum::{
    body::Bytes,
    extract::{
        Multipart, State,
        multipart::{MultipartError, MultipartRejection},
    },
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    mcp_settings::{
        ListenerKind,
        client_ca::{CaError, check_mtls_ca},
    },
    persist::{create_private_dir, write_atomic},
    settings::{McpConfig, mcp_schema::MtlsMode},
};
use kcc_i18n::{bundle::MessageKey, keys};
use secrecy::SecretString;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{
    Attached,
    flow::{audit, confirmed, in_background, name, outcome},
    messages::Said,
    page::{DIRECTORY, Failure, OIDC_CA},
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

/// The audited key of a client CA upload.
const MTLS_KEY: &str = "auth.mtls.ca";

/// Why an upload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A field besides `kind`, `file` and `password`, an unknown kind, or a missing one.
    Fields,
    /// The file is larger than [`FILE_LIMIT`].
    TooLarge,
    /// The file is not PEM certificates only.
    NotPem,
    /// The client CA holds more than ten certificates (how many).
    Count(usize),
    /// A client CA certificate cannot be read (its position, from 1).
    Unreadable(usize),
    /// A client CA certificate is not a CA (its position, from 1).
    NotCa(usize),
}

/// The CA file an upload names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The client CA of the client-certificate sign-in.
    Mtls,
    /// The identity provider's CA bundle.
    Oidc,
}

/// The fields of an upload.
struct Upload {
    /// Which file.
    kind: Kind,
    /// Its bytes.
    bytes: Bytes,
    /// The account's password, when typed.
    password: Option<SecretString>,
}

/// `POST /ui/admin/mcp/ca`: checks the file and stores it as the kind's CA.
// NOT cancel-safe: dropped after the hand-over to the listeners or the write, the change runs on
// unaudited.
pub(crate) async fn upload(
    State(state): State<WebState>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let (Some(admin), Some(attached)) = (state.admin(), state.mcp()) else {
        return unavailable(None);
    };
    let locale = user.locale();
    let read = match multipart {
        Ok(fields) => read(fields).await,
        Err(_rejection) => Err(Refusal::Fields),
    };
    let upload = match read.and_then(checked) {
        Ok(upload) => upload,
        Err(refusal) => return refused(&user, refusal),
    };
    if upload.kind == Kind::Mtls {
        return client_ca(&state, &user, Arc::clone(attached), upload).await;
    }
    let _changes = admin.lock().await;
    let dir = admin.state().dir().join(DIRECTORY);
    let written = spawn_blocking(move || {
        create_private_dir(&dir)?;
        write_atomic(&dir, OIDC_CA, &upload.bytes)
    })
    .await;
    match written {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(locale)),
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    }
    let params = json!({ "changed": ["auth.oidc.ca"], "restarted": [] });
    audit(&state, &user, params, "success").await;
    let said = Said::new(locale, keys::WEB_ADMIN_MCP_CA_SAVED, None);
    reply::notice(&state, &user, (said, "success"), StatusCode::OK).await
}

/// Hands the checked client CA to the listeners: after the password when a listener uses
/// client certificates (then those listeners restart in the background), at once
/// otherwise.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
async fn client_ca(
    state: &WebState,
    user: &CurrentUser,
    attached: Arc<Attached>,
    upload: Upload,
) -> Response {
    let locale = user.locale();
    let users = match users_now(state).await {
        Ok(users) => users,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let restarted: Vec<&str> = users.iter().map(|kind| name(*kind)).collect();
    let params = json!({ "changed": [MTLS_KEY], "restarted": restarted });
    let in_use = !users.is_empty();
    if in_use {
        let Some(password) = &upload.password else {
            let said = Said::new(locale, keys::WEB_ADMIN_MCP_MTLS_CA_PASSWORD, None);
            return reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY);
        };
        match confirmed(state, user, password).await {
            Ok(None) => {}
            Ok(Some((said, refusal))) => {
                audit(state, user, params, refusal).await;
                return reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY);
            }
            Err(answer) => return answer.into_response(),
        }
    }
    let change = attached
        .control()
        .replace_client_ca(upload.bytes.to_vec(), in_use);
    if in_use {
        return in_background(state, user, attached, (users, change, params)).await;
    }
    let result = change.await;
    audit(state, user, params, outcome(result)).await;
    match result {
        Ok(()) => {
            let said = Said::new(locale, keys::WEB_ADMIN_MCP_CA_SAVED, None);
            reply::notice(state, user, (said, "success"), StatusCode::OK).await
        }
        Err(refusal) => {
            let said = Said::refusal(locale, refusal);
            reply::notice(state, user, (said, "error"), StatusCode::CONFLICT).await
        }
    }
}

/// The listeners whose client-certificate sign-in is on in the effective settings.
///
/// # Errors
///
/// The settings cannot be read.
// cancel-safe: it only reads local state on a blocking thread.
async fn users_now(state: &WebState) -> Result<Vec<ListenerKind>, Failure> {
    let admin = state.admin().ok_or("no administration services")?;
    let (store, base) = (admin.state().clone(), admin.mcp().clone());
    let effective = spawn_blocking(move || base.effective(&store)).await??;
    Ok(mtls_users(effective.settings()))
}

/// The listeners of `mcp` whose client-certificate sign-in is on.
pub(crate) fn mtls_users(mcp: &McpConfig) -> Vec<ListenerKind> {
    let mut users = Vec::new();
    if mcp.auth.main.mtls != MtlsMode::Off {
        users.push(ListenerKind::Main);
    }
    if mcp.dedicated.enabled && mcp.auth.dedicated.mtls != MtlsMode::Off {
        users.push(ListenerKind::Dedicated);
    }
    users
}

/// The 422 answer to `refusal`.
fn refused(user: &CurrentUser, refusal: Refusal) -> Response {
    let locale = user.locale();
    let (key, position): (MessageKey, Option<usize>) = match refusal {
        Refusal::Fields => (keys::WEB_ADMIN_MCP_ERROR_UPLOAD_FIELDS, None),
        Refusal::TooLarge => (keys::WEB_ADMIN_MCP_ERROR_UPLOAD_SIZE, None),
        Refusal::NotPem => (keys::WEB_ADMIN_MCP_ERROR_UPLOAD_PEM, None),
        Refusal::Count(found) => (keys::WEB_ADMIN_MCP_MTLS_CA_COUNT, Some(found)),
        Refusal::Unreadable(index) => (keys::WEB_ADMIN_MCP_MTLS_CA_UNREADABLE, Some(index)),
        Refusal::NotCa(index) => (keys::WEB_ADMIN_MCP_MTLS_CA_NOT_CA, Some(index)),
    };
    let said = Said::new(
        locale,
        key,
        position.map(|value| ("value", value.to_string())),
    );
    reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY)
}

/// The kind, the file and the password of the upload; any other field refuses it.
///
/// # Errors
///
/// [`Refusal::Fields`] for another, repeated, missing or unreadable field,
/// [`Refusal::TooLarge`] past the body limit.
// cancel-safe: reads the request body only.
async fn read(mut fields: Multipart) -> Result<(String, Bytes, Option<SecretString>), Refusal> {
    let (mut named, mut sent, mut password) = (None, None, None);
    while let Some(field) = fields.next_field().await.map_err(|error| unread(&error))? {
        match field.name() {
            Some("kind") if named.is_none() => {
                named = Some(field.text().await.map_err(|error| unread(&error))?);
            }
            Some("file") if sent.is_none() => {
                sent = Some(field.bytes().await.map_err(|error| unread(&error))?);
            }
            Some("password") if password.is_none() => {
                let typed = field.text().await.map_err(|error| unread(&error))?;
                password = Some(SecretString::from(typed));
            }
            Some(_) | None => return Err(Refusal::Fields),
        }
    }
    let (kind, file) = named.zip(sent).ok_or(Refusal::Fields)?;
    Ok((kind, file, password))
}

/// The upload, once the file passed the checks of its kind.
///
/// # Errors
///
/// [`Refusal::Fields`] for an unknown kind, another [`Refusal`] for the file.
fn checked(
    (named, bytes, password): (String, Bytes, Option<SecretString>),
) -> Result<Upload, Refusal> {
    let kind = match named.as_str() {
        "mtls" => Kind::Mtls,
        "oidc" => Kind::Oidc,
        _ => return Err(Refusal::Fields),
    };
    if bytes.len() > FILE_LIMIT {
        return Err(Refusal::TooLarge);
    }
    match kind {
        Kind::Mtls => {
            let _subjects = check_mtls_ca(&bytes).map_err(|error| match error {
                CaError::TooLarge => Refusal::TooLarge,
                CaError::Count { found } => Refusal::Count(found),
                CaError::Unparsable { index } => Refusal::Unreadable(index.saturating_add(1)),
                CaError::NotCa { index } => Refusal::NotCa(index.saturating_add(1)),
                CaError::NotPem | CaError::OtherBlock | CaError::State(_) | _ => Refusal::NotPem,
            })?;
        }
        Kind::Oidc => {
            if pem::certificates(&bytes).is_none() {
                return Err(Refusal::NotPem);
            }
        }
    }
    Ok(Upload {
        kind,
        bytes,
        password,
    })
}

/// Why reading a multipart field failed.
fn unread(error: &MultipartError) -> Refusal {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Refusal::TooLarge
    } else {
        Refusal::Fields
    }
}
