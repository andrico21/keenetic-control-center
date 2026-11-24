//! `POST /ui/admin/mcp/ca`: the client CA or the identity provider's CA bundle.
//!
//! The file of at most 64 KiB is checked here as the listeners take it (one to ten CA
//! certificates), for both kinds. It goes to the running listeners, which store it in
//! their serialized section. Both files are trust anchors: the client CA decides who may
//! sign in with a certificate, the identity provider's bundle which certificate the JWKS
//! fetch trusts, and so which tokens are valid. Only a role that covers every role those
//! identities get (the certificates' role, the provider's mapping targets) may replace
//! either file, before any password is asked. While a listener uses the file, replacing
//! it reduces safety, so the form carries the account's password and the listeners using
//! it restart, polled like a settings restart. The upload takes no path and nothing of the
//! file reaches a page or the log.

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
        ListenerKind, SettingsError,
        client_ca::{CaError, check_mtls_ca},
        idp_ca::check_oidc_ca,
        sources::TrustAnchor,
    },
    settings::{
        McpConfig,
        mcp_schema::{MtlsMode, OauthMode},
    },
};
use kcc_i18n::{bundle::MessageKey, keys};
use secrecy::SecretString;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{
    Attached,
    flow::{audit, confirmed, in_background, name, outcome},
    messages::Said,
    page::Failure,
    reply,
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

impl Kind {
    /// The key the audit entry names as changed.
    const fn audited(self) -> &'static str {
        match self {
            Self::Mtls => "auth.mtls.ca",
            Self::Oidc => "auth.oidc.ca",
        }
    }

    /// Why the password is needed, when a listener uses the file.
    const fn password_needed(self) -> MessageKey {
        match self {
            Self::Mtls => keys::WEB_ADMIN_MCP_MTLS_CA_PASSWORD,
            Self::Oidc => keys::WEB_ADMIN_MCP_OIDC_CA_PASSWORD,
        }
    }

    /// The sign-in source whose identities the file admits.
    const fn anchor(self) -> TrustAnchor {
        match self {
            Self::Mtls => TrustAnchor::ClientCa,
            Self::Oidc => TrustAnchor::IdentityProvider,
        }
    }

    /// The listeners of `mcp` using the file.
    fn users(self, mcp: &McpConfig) -> Vec<ListenerKind> {
        match self {
            Self::Mtls => mtls_users(mcp),
            Self::Oidc => oidc_users(mcp),
        }
    }
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

/// `POST /ui/admin/mcp/ca`: checks the file and hands it to the listeners as the kind's
/// CA.
// NOT cancel-safe: dropped after the hand-over to the listeners, the change runs on unaudited.
pub(crate) async fn upload(
    State(state): State<WebState>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let (Some(_admin), Some(attached)) = (state.admin(), state.mcp()) else {
        return unavailable(None);
    };
    let read = match multipart {
        Ok(fields) => read(fields).await,
        Err(_rejection) => Err(Refusal::Fields),
    };
    match read.and_then(checked) {
        Ok(upload) => replaced(&state, &user, Arc::clone(attached), upload).await,
        Err(refusal) => refused(&user, refusal),
    }
}

/// Hands the checked file to the listeners once the acting role covers its roles.
///
/// Those are the roles the file lets sign in. Then the password when a listener uses it
/// (and those listeners restart in the background), at once otherwise.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
async fn replaced(
    state: &WebState,
    user: &CurrentUser,
    attached: Arc<Attached>,
    upload: Upload,
) -> Response {
    let locale = user.locale();
    let users = match users_now(state, user, upload.kind).await {
        Ok(Ok(users)) => users,
        Ok(Err(refusal)) => {
            return Said::plan(locale, &refusal).map_or_else(
                || errors::internal(&refusal, fragment_shell(locale)),
                |said| reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY),
            );
        }
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let restarted: Vec<&str> = users.iter().map(|kind| name(*kind)).collect();
    let params = json!({ "changed": [upload.kind.audited()], "restarted": restarted });
    let in_use = !users.is_empty();
    if in_use {
        let Some(password) = &upload.password else {
            let said = Said::new(locale, upload.kind.password_needed(), None);
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
    let control = attached.control();
    let pem = upload.bytes.to_vec();
    let change = match upload.kind {
        Kind::Mtls => control.replace_client_ca(pem, in_use),
        Kind::Oidc => control.replace_idp_ca(pem, in_use),
    };
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

/// The listeners using the `kind` file in the effective settings, or why `user` may not
/// replace it.
///
/// The file decides whose identities sign in, so the acting role must cover every role
/// they get.
///
/// # Errors
///
/// The administration services are missing or the blocking task failed.
// cancel-safe: it only reads local state on a blocking thread.
async fn users_now(
    state: &WebState,
    user: &CurrentUser,
    kind: Kind,
) -> Result<Result<Vec<ListenerKind>, SettingsError>, Failure> {
    let admin = state.admin().ok_or("no administration services")?;
    let (store, base, actor) = (
        admin.state().clone(),
        admin.mcp().clone(),
        user.role().clone(),
    );
    Ok(spawn_blocking(move || {
        base.check_ca_ceiling(&store, &actor, kind.anchor())?;
        Ok(kind.users(base.effective(&store)?.settings()))
    })
    .await?)
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

/// The listeners of `mcp` that sign in with the identity provider (`oauth = "external"`).
pub(crate) fn oidc_users(mcp: &McpConfig) -> Vec<ListenerKind> {
    let mut users = Vec::new();
    if mcp.auth.main.oauth == OauthMode::External {
        users.push(ListenerKind::Main);
    }
    if mcp.dedicated.enabled && mcp.auth.dedicated.oauth == OauthMode::External {
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
    let check = match kind {
        Kind::Mtls => check_mtls_ca,
        Kind::Oidc => check_oidc_ca,
    };
    let _subjects = check(&bytes).map_err(|error| match error {
        CaError::TooLarge => Refusal::TooLarge,
        CaError::Count { found } => Refusal::Count(found),
        CaError::Unparsable { index } => Refusal::Unreadable(index.saturating_add(1)),
        CaError::NotCa { index } => Refusal::NotCa(index.saturating_add(1)),
        CaError::NotPem | CaError::OtherBlock | CaError::State(_) | _ => Refusal::NotPem,
    })?;
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
