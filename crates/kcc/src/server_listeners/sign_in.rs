//! A listener's sign-in methods for its kit configuration.
//!
//! Client certificates over the uploaded client CA, kcc account tokens (`oauth = "kcc"`)
//! and another identity provider's tokens (`oauth = "external"`, [`external`]).

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

pub mod external;

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

/// The `kind` listener's token sign-in: the kit's OAuth configuration and, for kcc
/// tokens, what kcc's authorization server accepts; both `None` when its `oauth` is
/// `none`.
///
/// `kcc` needs kcc's authorization server (an issuer) and the internal JWKS listener;
/// `external` needs a usable identity provider ([`external::provider`]). A refusal's
/// reason is logged.
pub(super) fn tokens(
    shared: &Shared,
    settings: &McpConfig,
    kind: ListenerKind,
) -> Result<(Option<OAuthConfig>, Option<Activation>), BuildError> {
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
        OauthMode::None => Ok((None, None)),
        OauthMode::Kcc => {
            let sign_in = shared
                .sign_in
                .as_ref()
                .ok_or_else(|| refused(&"kcc's authorization server has no issuer"))?;
            let (oauth, activation) = sign_in
                .listener(&shared.config, settings, kind)
                .map_err(|reason| refused(&reason))?;
            Ok((Some(oauth), Some(activation)))
        }
        OauthMode::External | _ => external::provider(
            &shared.state,
            settings,
            &shared.config.mcp.auth.oidc,
        )
        .map(|oauth| (Some(oauth), None))
        .map_err(|refusal| {
            tracing::warn!(listener, reason = %refusal, "identity provider sign-in refused");
            BuildError::IdentityProvider(refusal)
        }),
    }
}
