//! The `[mcp]` rules serde cannot express.

use url::Host;

use super::{DedicatedListenerConfig, DedicatedTls, McpAuthConfig, McpConfig, MtlsMode};
use crate::{
    mcp_settings::keys::KeyPath,
    permissions::KCC_ACCOUNT_ROLE,
    settings::{ConfigError, invalid},
};

/// Checks the `[mcp]` rules serde cannot express; the same rules hold for the effective
/// settings a Web change would produce.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming the field.
pub(crate) fn validate(mcp: &McpConfig) -> Result<(), ConfigError> {
    if mcp.max_result_bytes == 0 {
        return Err(invalid("mcp.max_result_bytes", "must be at least 1"));
    }
    if let Some(key) = mcp
        .locked
        .iter()
        .find(|key| key.parse::<KeyPath>().is_err())
    {
        return Err(invalid(
            format!("mcp.locked.{key}"),
            "names no Web-managed [mcp] key",
        ));
    }
    if let Some(field) = reserved_role_field(mcp) {
        return Err(invalid(
            field,
            "the role kcc-account is reserved and cannot be named here",
        ));
    }
    if mcp.auth.main.mtls == MtlsMode::Required {
        return Err(invalid(
            "mcp.auth.main.mtls",
            "required is not allowed on the main listener, which also serves the Web UI",
        ));
    }
    validate_dedicated(&mcp.dedicated)?;
    validate_auth(&mcp.auth)
}

/// The first key that names the reserved role `kcc-account` as an MCP role target.
fn reserved_role_field(mcp: &McpConfig) -> Option<&'static str> {
    let reserved = |role: &str| role == KCC_ACCOUNT_ROLE;
    let oidc = &mcp.auth.oidc;
    [
        ("mcp.stdio_role", reserved(&mcp.stdio_role)),
        (
            "mcp.auth.mtls.default_role",
            mcp.auth.mtls.default_role.as_deref().is_some_and(reserved),
        ),
        (
            "mcp.auth.oidc.role_mappings",
            oidc.role_mappings
                .iter()
                .any(|mapping| reserved(&mapping.role)),
        ),
        (
            "mcp.auth.oidc.scopes",
            oidc.scopes.iter().any(|mapping| reserved(&mapping.role)),
        ),
    ]
    .into_iter()
    .find_map(|(field, named)| named.then_some(field))
}

/// Checks `[mcp.dedicated]`.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming the field.
fn validate_dedicated(dedicated: &DedicatedListenerConfig) -> Result<(), ConfigError> {
    if dedicated.port < 1024 {
        return Err(invalid(
            "mcp.dedicated.port",
            "must be at least 1024; this service never binds privileged ports",
        ));
    }
    let loopback = dedicated.bind.is_loopback();
    if dedicated.tls == DedicatedTls::None && !loopback {
        return Err(invalid(
            "mcp.dedicated.tls",
            "none is accepted only on a loopback bind",
        ));
    }
    if !loopback && dedicated.public_url.is_none() {
        return Err(invalid(
            "mcp.dedicated.public_url",
            "a non-loopback dedicated listener needs its public URL",
        ));
    }
    if let Some(url) = &dedicated.public_url
        && (!matches!(url.scheme(), "http" | "https")
            || url.cannot_be_a_base()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some())
    {
        return Err(invalid(
            "mcp.dedicated.public_url",
            "must be an http or https base URL without credentials, query or fragment",
        ));
    }
    Ok(())
}

/// Checks `[mcp.auth.*]`.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming the field.
fn validate_auth(auth: &McpAuthConfig) -> Result<(), ConfigError> {
    if auth.kcc.access_ttl.is_zero() {
        return Err(invalid("mcp.auth.kcc.access_ttl", "must be positive"));
    }
    if auth.kcc.refresh_ttl < auth.kcc.access_ttl {
        return Err(invalid(
            "mcp.auth.kcc.refresh_ttl",
            "must be at least mcp.auth.kcc.access_ttl",
        ));
    }
    let oidc = &auth.oidc;
    for (field, configured) in [
        ("mcp.auth.oidc.issuer", &oidc.issuer),
        ("mcp.auth.oidc.jwks_uri", &oidc.jwks_uri),
    ] {
        if let Some(url) = configured
            && (url.scheme() != "https" || !matches!(url.host(), Some(Host::Domain(_))))
        {
            return Err(invalid(
                field,
                "must be an https URL whose host is a name, not an IP address",
            ));
        }
    }
    let empty = |text: &str| text.trim().is_empty();
    if oidc.audience.as_deref().is_some_and(empty)
        || oidc.role_claim.as_deref().is_some_and(empty)
        || oidc.allowed_algorithms.iter().any(|name| empty(name))
        || oidc
            .role_mappings
            .iter()
            .any(|mapping| empty(&mapping.claim_value) || empty(&mapping.role))
        || oidc
            .scopes
            .iter()
            .any(|mapping| empty(&mapping.scope) || empty(&mapping.role))
    {
        return Err(invalid(
            "mcp.auth.oidc",
            "audience, role_claim, algorithm names and mapping entries must not be empty",
        ));
    }
    Ok(())
}
