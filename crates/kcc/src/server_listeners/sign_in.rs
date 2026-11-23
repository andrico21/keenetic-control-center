//! A listener's sign-in methods for its kit configuration: client certificates over the
//! uploaded client CA; OAuth is refused until it is wired.

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
use rmcp_server_kit::auth::MtlsConfig;
use serde_json::{Map, Value};

use super::{
    build::{BuildError, Shared},
    name,
};

/// The `kind` listener's client-certificate sign-in; `None` when off.
///
/// Otherwise the kit's configuration over the uploaded client CA (read and checked now),
/// with the default role and the kit's CRL defaults. OAuth is refused: this version cannot
/// enforce it, so it is never silently ignored.
pub(super) fn client_certificates(
    shared: &Shared,
    settings: &McpConfig,
    kind: ListenerKind,
) -> Result<Option<MtlsConfig>, BuildError> {
    let auth: ListenerAuth = match kind {
        ListenerKind::Main => settings.auth.main,
        ListenerKind::Dedicated | _ => settings.auth.dedicated,
    };
    if auth.oauth != OauthMode::None {
        return Err(BuildError::SignInUnavailable {
            listener: name(kind),
        });
    }
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
