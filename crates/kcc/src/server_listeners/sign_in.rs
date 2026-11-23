//! A listener's sign-in methods for its kit configuration.
//!
//! Client certificates over the uploaded client CA, and kcc account tokens
//! (`oauth = "kcc"`); another identity provider (`oauth = "external"`) is refused until it
//! is wired.

use core::fmt::Display;
use std::fs;

use kcc_app::{
    mcp_settings::{
        ListenerKind,
        client_ca::{check_mtls_ca, mtls_ca_path},
    },
    settings::{
        McpConfig,
        mcp_schema::{ListenerAuth, MtlsMode, OauthMode},
    },
};
use kcc_web::oauth::Activation;
use rmcp_server_kit::{auth::MtlsConfig, oauth::OAuthConfig};
use serde_json::{Map, Value};

use super::{
    build::{BuildError, Shared},
    name,
};

/// The `kind` listener's client-certificate sign-in; `None` when off.
///
/// Otherwise the kit's configuration over the uploaded client CA (read and checked now),
/// with the default role and the kit's CRL defaults.
pub(super) fn client_certificates(
    shared: &Shared,
    settings: &McpConfig,
    kind: ListenerKind,
) -> Result<Option<MtlsConfig>, BuildError> {
    let auth: ListenerAuth = match kind {
        ListenerKind::Main => settings.auth.main,
        ListenerKind::Dedicated | _ => settings.auth.dedicated,
    };
    let required = match auth.mtls {
        MtlsMode::Required => true,
        MtlsMode::Optional => false,
        MtlsMode::Off | _ => return Ok(None),
    };
    let path = mtls_ca_path(&shared.state);
    let unusable =
        |error: &dyn Display| BuildError::ClientCa(format!("{}: {error}", path.display()));
    let pem = fs::read(&path).map_err(|error| unusable(&error))?;
    let _subjects = check_mtls_ca(&pem).map_err(|error| unusable(&error))?;
    let mut fields = Map::new();
    let ca_cert_path = serde_json::to_value(&path).map_err(|error| unusable(&error))?;
    drop(fields.insert("ca_cert_path".to_owned(), ca_cert_path));
    drop(fields.insert("required".to_owned(), Value::Bool(required)));
    if let Some(role) = &settings.auth.mtls.default_role {
        drop(fields.insert("default_role".to_owned(), Value::String(role.clone())));
    }
    serde_json::from_value(Value::Object(fields))
        .map(Some)
        .map_err(|error| unusable(&error))
}

/// The `kind` listener's kcc token sign-in and what it accepts; `None` when its `oauth`
/// is `none`.
///
/// `kcc` needs kcc's authorization server (an issuer) and the internal JWKS listener;
/// `external` is refused: this version cannot enforce it, so it is never silently
/// ignored. A refusal's reason is logged.
pub(super) fn kcc_tokens(
    shared: &Shared,
    settings: &McpConfig,
    kind: ListenerKind,
) -> Result<Option<(OAuthConfig, Activation)>, BuildError> {
    let listener = name(kind);
    let refused = |reason: &dyn Display| {
        tracing::warn!(listener, %reason, "kcc sign-in refused");
        BuildError::SignInUnavailable { listener }
    };
    let mode = match kind {
        ListenerKind::Main => settings.auth.main.oauth,
        ListenerKind::Dedicated | _ => settings.auth.dedicated.oauth,
    };
    match mode {
        OauthMode::None => Ok(None),
        OauthMode::Kcc => {
            let sign_in = shared
                .sign_in
                .as_ref()
                .ok_or_else(|| refused(&"kcc's authorization server has no issuer"))?;
            sign_in
                .listener(&shared.config, settings, kind)
                .map(Some)
                .map_err(|reason| refused(&reason))
        }
        OauthMode::External | _ => Err(refused(&"an external identity provider is not wired")),
    }
}
