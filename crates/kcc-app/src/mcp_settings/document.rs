//! `mcp_settings.json`: the `[mcp]` values changed on the Web, mirroring the kcc.toml
//! tables. An absent key keeps the kcc.toml value.

use core::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    persist::{Migration, StateDoc},
    settings::mcp_schema::{
        DedicatedTls, Endpoint, MtlsMode, OauthMode, RoleMapping, ScopeMapping,
    },
};

/// The Web-managed MCP settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the state document's name says which file it is beside the other documents"
)]
pub struct McpSettingsDocument {
    /// Raised by every saved change; a change planned on another revision is refused.
    pub revision: u64,
    /// The values set on the Web.
    pub overrides: McpOverrides,
}

impl StateDoc for McpSettingsDocument {
    const FILE_NAME: &'static str = "mcp_settings.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// Optional values for the Web-managed `[mcp]` keys; also the shape of a change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct McpOverrides {
    /// `http_enabled`.
    pub http_enabled: Option<bool>,
    /// `stdio_enabled`.
    pub stdio_enabled: Option<bool>,
    /// `stdio_role`.
    pub stdio_role: Option<String>,
    /// `read_only`.
    pub read_only: Option<bool>,
    /// `allow_destructive`.
    pub allow_destructive: Option<bool>,
    /// `max_result_bytes`.
    pub max_result_bytes: Option<u32>,
    /// `toolsets`.
    pub toolsets: Option<Vec<String>>,
    /// `endpoint`.
    pub endpoint: Option<Endpoint>,
    /// `[mcp.dedicated]`.
    pub dedicated: DedicatedOverrides,
    /// `[mcp.auth]`.
    pub auth: AuthOverrides,
}

/// `[mcp.dedicated]` values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct DedicatedOverrides {
    /// `enabled`.
    pub enabled: Option<bool>,
    /// `bind`.
    pub bind: Option<IpAddr>,
    /// `port`.
    pub port: Option<u16>,
    /// `public_url`.
    pub public_url: Option<Url>,
    /// `tls`.
    pub tls: Option<DedicatedTls>,
}

/// `[mcp.auth]` values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct AuthOverrides {
    /// `[mcp.auth.main]`.
    pub main: ListenerAuthOverrides,
    /// `[mcp.auth.dedicated]`.
    pub dedicated: ListenerAuthOverrides,
    /// `[mcp.auth.kcc]`.
    pub kcc: KccOverrides,
    /// `[mcp.auth.oidc]` without the kcc.toml-only SSRF allowlists.
    pub oidc: OidcOverrides,
    /// `[mcp.auth.mtls]`.
    pub mtls: MtlsOverrides,
}

/// `[mcp.auth.main]` or `[mcp.auth.dedicated]` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct ListenerAuthOverrides {
    /// `oauth`.
    pub oauth: Option<OauthMode>,
    /// `mtls`.
    pub mtls: Option<MtlsMode>,
}

/// `[mcp.auth.kcc]` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct KccOverrides {
    /// `access_ttl`.
    #[serde(with = "humantime_serde::option")]
    pub access_ttl: Option<Duration>,
    /// `refresh_ttl`.
    #[serde(with = "humantime_serde::option")]
    pub refresh_ttl: Option<Duration>,
}

/// `[mcp.auth.oidc]` values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct OidcOverrides {
    /// `issuer`.
    pub issuer: Option<Url>,
    /// `audience`.
    pub audience: Option<String>,
    /// `jwks_uri`.
    pub jwks_uri: Option<Url>,
    /// `role_claim`.
    pub role_claim: Option<String>,
    /// `role_mappings`.
    pub role_mappings: Option<Vec<RoleMapping>>,
    /// `scopes`.
    pub scopes: Option<Vec<ScopeMapping>>,
    /// `allowed_algorithms`.
    pub allowed_algorithms: Option<Vec<String>>,
}

/// `[mcp.auth.mtls]` values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct MtlsOverrides {
    /// `default_role`.
    pub default_role: Option<String>,
}
