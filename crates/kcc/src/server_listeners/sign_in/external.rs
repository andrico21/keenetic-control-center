//! The kit's OAuth configuration of a listener with `oauth = "external"`: another
//! identity provider's tokens, validated by the kit in resource-server mode.
//!
//! The provider's issuer, audience, JWKS URL, role mapping and algorithms come from the
//! effective settings; the SSRF allowlist only from kcc.toml (the Web cannot set it); the
//! provider's CA bundle from `<state>/mcp/oidc-ca.pem`, checked as the Web checked it. The
//! JWKS host is resolved and screened now, so a provider on a private, loopback or
//! link-local address that kcc.toml does not admit refuses the build with its reason
//! instead of failing every token later; the kit screens every fetch again.

use kcc_app::{
    mcp_settings::idp_ca::{check_oidc_ca, oidc_ca_path, read_oidc_ca},
    persist::StateStore,
    settings::{McpConfig, mcp_schema::OidcConfig},
};
use rmcp_server_kit::oauth::OAuthConfig;
use serde_json::{Map, Value, json};

mod screen;

/// Why a listener cannot validate the identity provider's tokens.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderRefusal {
    /// A required `[mcp.auth.oidc]` key is not set.
    #[error("[mcp.auth.oidc] {0} is not set")]
    Missing(&'static str),
    /// The JWKS host resolves to an address kcc.toml's SSRF allowlist does not admit.
    #[error(
        "the JWKS host {host} resolves to a {reason} address; only [mcp.auth.oidc] ssrf_allow_hosts or ssrf_allow_cidrs in kcc.toml admit it"
    )]
    PrivateAddress {
        /// The JWKS URL's host.
        host: String,
        /// The address class, as the kit names it (`loopback`, `private_rfc1918`, ...).
        reason: &'static str,
    },
    /// The JWKS host resolves to a cloud metadata address, which nothing admits.
    #[error("the JWKS host {host} resolves to a cloud metadata address")]
    Metadata {
        /// The JWKS URL's host.
        host: String,
    },
    /// The stored identity provider CA bundle cannot be read or fails the checks.
    #[error("identity provider CA bundle {0}")]
    CaBundle(String),
    /// The kit refused the configuration.
    #[error("{0}")]
    Kit(String),
}

/// The kit's OAuth configuration for the provider of `settings`, with kcc.toml's
/// `allowlist` and the CA bundle stored in `state`.
///
/// # Errors
///
/// [`ProviderRefusal`].
pub(crate) fn provider(
    state: &StateStore,
    settings: &McpConfig,
    allowlist: &OidcConfig,
) -> Result<OAuthConfig, ProviderRefusal> {
    let oidc = &settings.auth.oidc;
    let issuer = oidc
        .issuer
        .as_ref()
        .ok_or(ProviderRefusal::Missing("issuer"))?;
    let audience = oidc
        .audience
        .as_deref()
        .ok_or(ProviderRefusal::Missing("audience"))?;
    let jwks = oidc
        .jwks_uri
        .as_ref()
        .ok_or(ProviderRefusal::Missing("jwks_uri"))?;
    screen::screen(jwks, allowlist)?;
    let mut fields = Map::new();
    let mut set = |name: &str, value: Value| drop(fields.insert(name.to_owned(), value));
    set("issuer", json!(issuer.as_str()));
    set("audience", json!(audience));
    set("jwks_uri", json!(jwks.as_str()));
    set("require_subject", Value::Bool(true));
    set("authorization_servers", json!([issuer.as_str()]));
    set("audience_validation_mode", json!("strict"));
    match &oidc.role_claim {
        Some(claim) => {
            set("role_claim", json!(claim));
            set("role_mappings", json!(oidc.role_mappings));
        }
        None => set("scopes", json!(oidc.scopes)),
    }
    if !oidc.allowed_algorithms.is_empty() {
        set("allowed_algorithms", json!(oidc.allowed_algorithms));
    }
    let (hosts, cidrs) = (&allowlist.ssrf_allow_hosts, &allowlist.ssrf_allow_cidrs);
    if !hosts.is_empty() || !cidrs.is_empty() {
        let networks: Vec<String> = cidrs.iter().map(ToString::to_string).collect();
        set(
            "ssrf_allowlist",
            json!({ "hosts": hosts, "cidrs": networks }),
        );
    }
    let path = oidc_ca_path(state);
    let bundle = |error: &dyn core::fmt::Display| {
        ProviderRefusal::CaBundle(format!("{}: {error}", path.display()))
    };
    if let Some(pem) = read_oidc_ca(state).map_err(|error| bundle(&error))? {
        let _subjects = check_oidc_ca(&pem).map_err(|error| bundle(&error))?;
        set("ca_cert_path", json!(path));
    }
    let oauth: OAuthConfig = serde_json::from_value(Value::Object(fields))
        .map_err(|error| ProviderRefusal::Kit(error.to_string()))?;
    oauth
        .validate()
        .map_err(|error| ProviderRefusal::Kit(error.to_string()))?;
    Ok(oauth)
}
