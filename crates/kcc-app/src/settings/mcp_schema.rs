//! The tables below `[mcp]`: the dedicated MCP listener and the sign-in methods.
//!
//! The same shapes are the Web-managed overrides of `mcp_settings.json`, so every type
//! here serializes as well as it parses.

extern crate alloc;

pub(crate) mod checks;

use alloc::collections::BTreeSet;
use core::{
    iter,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use url::Url;

use super::McpConfig;

/// Which listener serves MCP (`[mcp] endpoint`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Endpoint {
    /// `/mcp` on the main listener, beside the Web UI.
    #[default]
    Main,
    /// Only the dedicated MCP listener.
    Dedicated,
    /// Both listeners.
    Both,
}

/// How the dedicated listener gets its TLS certificate (`[mcp.dedicated] tls`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DedicatedTls {
    /// The main listener's certificate and key.
    #[default]
    Main,
    /// A self-signed certificate kcc generates.
    SelfSigned,
    /// Plain HTTP; accepted only on a loopback bind.
    None,
}

/// `[mcp.dedicated]`: the optional MCP-only listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct DedicatedListenerConfig {
    /// Run the dedicated listener.
    pub enabled: bool,
    /// Address it binds.
    pub bind: IpAddr,
    /// Port it binds.
    pub port: u16,
    /// Externally reachable base URL; required for a non-loopback bind.
    pub public_url: Option<Url>,
    /// Certificate source.
    pub tls: DedicatedTls,
}

impl Default for DedicatedListenerConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: false,
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8444,
            public_url: None,
            tls: DedicatedTls::Main,
        }
    }
}

/// OAuth sign-in of one listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OauthMode {
    /// API keys only.
    #[default]
    None,
    /// kcc is its own authorization server (kcc accounts).
    Kcc,
    /// Tokens of an external OIDC identity provider (`[mcp.auth.oidc]`).
    External,
}

/// Client certificate sign-in of one listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MtlsMode {
    /// No client certificates.
    #[default]
    Off,
    /// A certificate from the uploaded CA signs in; other methods still work.
    Optional,
    /// Every connection needs a certificate (dedicated listener only).
    Required,
}

/// `[mcp.auth.main]` and `[mcp.auth.dedicated]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct ListenerAuth {
    /// OAuth method.
    pub oauth: OauthMode,
    /// Client certificate method.
    pub mtls: MtlsMode,
}

/// `[mcp.auth]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct McpAuthConfig {
    /// Sign-in methods of the main listener.
    pub main: ListenerAuth,
    /// Sign-in methods of the dedicated listener.
    pub dedicated: ListenerAuth,
    /// kcc as authorization server.
    pub kcc: KccAsConfig,
    /// The external OIDC identity provider.
    pub oidc: OidcConfig,
    /// Client certificate sign-in.
    pub mtls: MtlsSettings,
}

/// `[mcp.auth.kcc]`: token lifetimes of kcc's own authorization server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct KccAsConfig {
    /// Access token lifetime.
    #[serde(with = "humantime_serde")]
    pub access_ttl: Duration,
    /// Refresh token lifetime.
    #[serde(with = "humantime_serde")]
    pub refresh_ttl: Duration,
}

impl Default for KccAsConfig {
    #[inline]
    fn default() -> Self {
        Self {
            access_ttl: Duration::from_mins(15),
            refresh_ttl: Duration::from_hours(7 * 24),
        }
    }
}

/// `[mcp.auth.oidc]`: the external identity provider in resource-server mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct OidcConfig {
    /// Token issuer (`iss`); https, not an IP address.
    pub issuer: Option<Url>,
    /// Expected audience (`aud`).
    pub audience: Option<String>,
    /// JWKS URL; https, not an IP address.
    pub jwks_uri: Option<Url>,
    /// Claim holding role values; scopes are mapped when unset.
    pub role_claim: Option<String>,
    /// Claim value to kcc role.
    pub role_mappings: Vec<RoleMapping>,
    /// Scope to kcc role.
    pub scopes: Vec<ScopeMapping>,
    /// Accepted signing algorithms; empty means the kit's default set.
    pub allowed_algorithms: Vec<String>,
    /// Private host names the identity provider may resolve to (kcc.toml only).
    pub ssrf_allow_hosts: Vec<String>,
    /// Private networks the identity provider may resolve to (kcc.toml only).
    pub ssrf_allow_cidrs: Vec<IpNet>,
}

/// One `[[mcp.auth.oidc.role_mappings]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleMapping {
    /// Value of the role claim.
    pub claim_value: String,
    /// kcc role granted for it.
    pub role: String,
}

impl RoleMapping {
    /// Maps the claim value `claim_value` to `role`.
    #[inline]
    #[must_use]
    pub const fn new(claim_value: String, role: String) -> Self {
        Self { claim_value, role }
    }
}

/// One `[[mcp.auth.oidc.scopes]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ScopeMapping {
    /// OAuth scope.
    pub scope: String,
    /// kcc role granted for it.
    pub role: String,
}

impl ScopeMapping {
    /// Maps the scope `scope` to `role`.
    #[inline]
    #[must_use]
    pub const fn new(scope: String, role: String) -> Self {
        Self { scope, role }
    }
}

/// `[mcp.auth.mtls]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct MtlsSettings {
    /// Role of a client signed in by certificate.
    pub default_role: Option<String>,
}

/// Every role the settings name: the stdio role, the mTLS role and the OIDC mapping
/// targets.
#[inline]
#[must_use]
pub fn named_roles(mcp: &McpConfig) -> BTreeSet<String> {
    let oidc = &mcp.auth.oidc;
    iter::once(mcp.stdio_role.clone())
        .chain(mcp.auth.mtls.default_role.clone())
        .chain(
            oidc.role_mappings
                .iter()
                .map(|mapping| mapping.role.clone()),
        )
        .chain(oidc.scopes.iter().map(|mapping| mapping.role.clone()))
        .collect()
}
