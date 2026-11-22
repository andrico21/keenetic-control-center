//! The seven sections of the page over the effective settings: tools, endpoints, sign-in
//! of each listener, kcc sign-in, the identity provider and client certificates.

use core::time::Duration;

use kcc_app::{mcp_settings::keys::KeyPath, settings::McpConfig};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{Choice, Control, Facts, Mappings, rows::Rows, view::Section};

/// Signing algorithms an identity provider may use; none symmetric.
const ALGORITHMS: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// OAuth choices of a listener.
const OAUTH: [(&str, MessageKey); 3] = [
    ("none", keys::WEB_ADMIN_MCP_OAUTH_NONE),
    ("kcc", keys::WEB_ADMIN_MCP_OAUTH_KCC),
    ("external", keys::WEB_ADMIN_MCP_OAUTH_EXTERNAL),
];

/// Client-certificate choices of the dedicated listener; the main one has the first two.
const MTLS: [(&str, MessageKey); 3] = [
    ("off", keys::WEB_ADMIN_MCP_MTLS_OFF),
    ("optional", keys::WEB_ADMIN_MCP_MTLS_OPTIONAL),
    ("required", keys::WEB_ADMIN_MCP_MTLS_REQUIRED),
];

/// The seven sections of `mcp`.
pub(super) fn sections(rows: &Rows<'_>, mcp: &McpConfig, facts: &Facts) -> [Section; 7] {
    let [tools, endpoints] = transport(rows, mcp, facts);
    let [signin_main, signin_dedicated, kcc] = signin(rows, mcp);
    let [idp, certs] = identity(rows, mcp, &facts.roles);
    [
        tools,
        endpoints,
        signin_main,
        signin_dedicated,
        kcc,
        idp,
        certs,
    ]
}

/// Tools and endpoints.
fn transport(rows: &Rows<'_>, mcp: &McpConfig, facts: &Facts) -> [Section; 2] {
    let toolsets = facts
        .toolsets
        .iter()
        .map(|toolset| Choice {
            reduces: toolset.safety_reducing,
            ..Choice::new(
                toolset.name.clone(),
                toolset.name.clone(),
                mcp.toolsets.contains(&toolset.name),
            )
        })
        .collect();
    let dedicated = &mcp.dedicated;
    [
        Section::new(
            "mcp-tools",
            vec![
                rows.row(KeyPath::Toolsets, Control::Checks(toolsets)),
                rows.check(KeyPath::ReadOnly, mcp.read_only),
                rows.check(KeyPath::AllowDestructive, mcp.allow_destructive),
                rows.row(
                    KeyPath::MaxResultBytes,
                    Control::Text(mcp.max_result_bytes.to_string(), "number"),
                ),
                rows.check(KeyPath::StdioEnabled, mcp.stdio_enabled),
                rows.role(KeyPath::StdioRole, Some(&mcp.stdio_role), &facts.roles),
            ],
        ),
        Section::new(
            "mcp-endpoints",
            vec![
                rows.check(KeyPath::HttpEnabled, mcp.http_enabled),
                rows.select(
                    KeyPath::Endpoint,
                    &mcp.endpoint,
                    &[
                        ("main", keys::WEB_ADMIN_MCP_ENDPOINT_MAIN),
                        ("dedicated", keys::WEB_ADMIN_MCP_ENDPOINT_DEDICATED),
                        ("both", keys::WEB_ADMIN_MCP_ENDPOINT_BOTH),
                    ],
                ),
                rows.check(KeyPath::DedicatedEnabled, dedicated.enabled),
                rows.text(KeyPath::DedicatedBind, Some(dedicated.bind.to_string())),
                rows.row(
                    KeyPath::DedicatedPort,
                    Control::Text(dedicated.port.to_string(), "number"),
                ),
                rows.text(
                    KeyPath::DedicatedPublicUrl,
                    dedicated.public_url.as_ref().map(ToString::to_string),
                ),
                rows.select(
                    KeyPath::DedicatedTls,
                    &dedicated.tls,
                    &[
                        ("main", keys::WEB_ADMIN_MCP_TLS_MAIN),
                        ("self_signed", keys::WEB_ADMIN_MCP_TLS_SELF_SIGNED),
                        ("none", keys::WEB_ADMIN_MCP_TLS_NONE),
                    ],
                ),
            ],
        ),
    ]
}

/// Sign-in of each listener and kcc sign-in.
fn signin(rows: &Rows<'_>, mcp: &McpConfig) -> [Section; 3] {
    let auth = &mcp.auth;
    let main_mtls = MTLS.get(..2).unwrap_or(&MTLS);
    let lifetime = |value: Duration| Some(humantime::format_duration(value).to_string());
    [
        Section::new(
            "mcp-signin-main",
            vec![
                rows.select(KeyPath::MainOauth, &auth.main.oauth, &OAUTH),
                rows.select(KeyPath::MainMtls, &auth.main.mtls, main_mtls),
            ],
        ),
        Section::new(
            "mcp-signin-dedicated",
            vec![
                rows.select(KeyPath::DedicatedOauth, &auth.dedicated.oauth, &OAUTH),
                rows.select(KeyPath::DedicatedMtls, &auth.dedicated.mtls, &MTLS),
            ],
        ),
        Section::new(
            "mcp-kcc",
            vec![
                rows.text(KeyPath::KccAccessTtl, lifetime(auth.kcc.access_ttl)),
                rows.text(KeyPath::KccRefreshTtl, lifetime(auth.kcc.refresh_ttl)),
            ],
        ),
    ]
}

/// The identity provider and client certificates.
fn identity(rows: &Rows<'_>, mcp: &McpConfig, roles: &[String]) -> [Section; 2] {
    let oidc = &mcp.auth.oidc;
    let table = |(first, second), heading, mut entries: Vec<(String, String)>| {
        entries.push((String::new(), String::new()));
        Control::Mappings(Mappings {
            first,
            second,
            heading: rows.say(heading),
            rows: entries,
            roles: roles.to_vec(),
        })
    };
    let claims = oidc
        .role_mappings
        .iter()
        .map(|mapping| (mapping.claim_value.clone(), mapping.role.clone()))
        .collect();
    let scopes = oidc
        .scopes
        .iter()
        .map(|mapping| (mapping.scope.clone(), mapping.role.clone()))
        .collect();
    let algorithms = ALGORITHMS
        .iter()
        .map(|name| {
            let chosen = oidc.allowed_algorithms.iter().any(|known| known == name);
            Choice::new((*name).to_owned(), (*name).to_owned(), chosen)
        })
        .collect();
    let link = |url: Option<&url::Url>| url.map(ToString::to_string);
    [
        Section::new(
            "mcp-idp",
            vec![
                rows.text(KeyPath::OidcIssuer, link(oidc.issuer.as_ref())),
                rows.text(KeyPath::OidcAudience, oidc.audience.clone()),
                rows.text(KeyPath::OidcJwksUri, link(oidc.jwks_uri.as_ref())),
                rows.text(KeyPath::OidcRoleClaim, oidc.role_claim.clone()),
                rows.row(
                    KeyPath::OidcRoleMappings,
                    table(
                        ("mapping_claim", "mapping_role"),
                        keys::WEB_ADMIN_MCP_MAPPING_CLAIM,
                        claims,
                    ),
                ),
                rows.row(
                    KeyPath::OidcScopes,
                    table(
                        ("scope_name", "scope_role"),
                        keys::WEB_ADMIN_MCP_MAPPING_SCOPE,
                        scopes,
                    ),
                ),
                rows.row(KeyPath::OidcAllowedAlgorithms, Control::Checks(algorithms)),
            ],
        ),
        Section::new(
            "mcp-certs",
            vec![rows.role(
                KeyPath::MtlsDefaultRole,
                mcp.auth.mtls.default_role.as_deref(),
                roles,
            )],
        ),
    ]
}
