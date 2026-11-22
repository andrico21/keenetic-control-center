//! One posted key: its value parsed and set in the change when it differs from the
//! effective settings.

use core::net::IpAddr;

use kcc_app::{
    mcp_settings::{Effective, document::McpOverrides, keys::KeyPath},
    settings::mcp_schema::{RoleMapping, ScopeMapping},
};

use super::{
    assign::{check, choice, filled, lifetime, set, set_optional, url},
    form::Submitted,
};

/// Sets `key` in `change` when its posted value differs from `effective`; `None`
/// when the value does not parse.
pub(super) fn assign(
    form: &Submitted<'_>,
    key: KeyPath,
    (effective, change): (&Effective, &mut McpOverrides),
) -> Option<()> {
    let now = effective.settings();
    let text = form.value(key.as_str()).map_or("", str::trim);
    let (dedicated, auth) = (&mut change.dedicated, &mut change.auth);
    match key {
        KeyPath::HttpEnabled => set(&mut change.http_enabled, &now.http_enabled, check(text)?),
        KeyPath::StdioEnabled => {
            set(&mut change.stdio_enabled, &now.stdio_enabled, check(text)?);
        }
        KeyPath::StdioRole => {
            set_optional(&mut change.stdio_role, Some(&now.stdio_role), filled(text));
        }
        KeyPath::ReadOnly => set(&mut change.read_only, &now.read_only, check(text)?),
        KeyPath::AllowDestructive => {
            set(
                &mut change.allow_destructive,
                &now.allow_destructive,
                check(text)?,
            );
        }
        KeyPath::MaxResultBytes => {
            set(
                &mut change.max_result_bytes,
                &now.max_result_bytes,
                text.parse().ok()?,
            );
        }
        KeyPath::Toolsets => set(&mut change.toolsets, &now.toolsets, form.list(key)),
        KeyPath::Endpoint => set(&mut change.endpoint, &now.endpoint, choice(text)?),
        KeyPath::DedicatedEnabled => {
            set(&mut dedicated.enabled, &now.dedicated.enabled, check(text)?);
        }
        KeyPath::DedicatedBind => {
            set(
                &mut dedicated.bind,
                &now.dedicated.bind,
                text.parse::<IpAddr>().ok()?,
            );
        }
        KeyPath::DedicatedPort => {
            set(&mut dedicated.port, &now.dedicated.port, text.parse().ok()?);
        }
        KeyPath::DedicatedPublicUrl => {
            let address = url(text).ok()?;
            set_optional(
                &mut dedicated.public_url,
                now.dedicated.public_url.as_ref(),
                address,
            );
        }
        KeyPath::DedicatedTls => set(&mut dedicated.tls, &now.dedicated.tls, choice(text)?),
        KeyPath::MainOauth => set(&mut auth.main.oauth, &now.auth.main.oauth, choice(text)?),
        KeyPath::MainMtls => set(&mut auth.main.mtls, &now.auth.main.mtls, choice(text)?),
        KeyPath::DedicatedOauth => {
            set(
                &mut auth.dedicated.oauth,
                &now.auth.dedicated.oauth,
                choice(text)?,
            );
        }
        KeyPath::DedicatedMtls => {
            set(
                &mut auth.dedicated.mtls,
                &now.auth.dedicated.mtls,
                choice(text)?,
            );
        }
        KeyPath::KccAccessTtl => {
            set(
                &mut auth.kcc.access_ttl,
                &now.auth.kcc.access_ttl,
                lifetime(text)?,
            );
        }
        KeyPath::KccRefreshTtl => {
            set(
                &mut auth.kcc.refresh_ttl,
                &now.auth.kcc.refresh_ttl,
                lifetime(text)?,
            );
        }
        KeyPath::OidcIssuer
        | KeyPath::OidcAudience
        | KeyPath::OidcJwksUri
        | KeyPath::OidcRoleClaim
        | KeyPath::OidcRoleMappings
        | KeyPath::OidcScopes
        | KeyPath::OidcAllowedAlgorithms
        | KeyPath::MtlsDefaultRole
        | _ => identity(form, key, (effective, change))?,
    }
    Some(())
}

/// [`assign`] for the identity provider and client certificate keys.
fn identity(
    form: &Submitted<'_>,
    key: KeyPath,
    (effective, change): (&Effective, &mut McpOverrides),
) -> Option<()> {
    let now = &effective.settings().auth;
    let text = form.value(key.as_str()).map_or("", str::trim);
    let (oidc, mtls) = (&mut change.auth.oidc, &mut change.auth.mtls);
    match key {
        KeyPath::OidcIssuer => {
            set_optional(&mut oidc.issuer, now.oidc.issuer.as_ref(), url(text).ok()?);
        }
        KeyPath::OidcAudience => {
            set_optional(&mut oidc.audience, now.oidc.audience.as_ref(), filled(text));
        }
        KeyPath::OidcJwksUri => {
            set_optional(
                &mut oidc.jwks_uri,
                now.oidc.jwks_uri.as_ref(),
                url(text).ok()?,
            );
        }
        KeyPath::OidcRoleClaim => {
            set_optional(
                &mut oidc.role_claim,
                now.oidc.role_claim.as_ref(),
                filled(text),
            );
        }
        KeyPath::OidcRoleMappings => {
            let rows = form.rows(("mapping_claim", "mapping_role"))?;
            let mappings = rows
                .into_iter()
                .map(|(claim, role)| RoleMapping::new(claim, role))
                .collect();
            set(&mut oidc.role_mappings, &now.oidc.role_mappings, mappings);
        }
        KeyPath::OidcScopes => {
            let rows = form.rows(("scope_name", "scope_role"))?;
            let scopes = rows
                .into_iter()
                .map(|(scope, role)| ScopeMapping::new(scope, role))
                .collect();
            set(&mut oidc.scopes, &now.oidc.scopes, scopes);
        }
        KeyPath::OidcAllowedAlgorithms => {
            set(
                &mut oidc.allowed_algorithms,
                &now.oidc.allowed_algorithms,
                form.list(key),
            );
        }
        KeyPath::MtlsDefaultRole => {
            set_optional(
                &mut mtls.default_role,
                now.mtls.default_role.as_ref(),
                filled(text),
            );
        }
        KeyPath::HttpEnabled
        | KeyPath::StdioEnabled
        | KeyPath::StdioRole
        | KeyPath::ReadOnly
        | KeyPath::AllowDestructive
        | KeyPath::MaxResultBytes
        | KeyPath::Toolsets
        | KeyPath::Endpoint
        | KeyPath::DedicatedEnabled
        | KeyPath::DedicatedBind
        | KeyPath::DedicatedPort
        | KeyPath::DedicatedPublicUrl
        | KeyPath::DedicatedTls
        | KeyPath::MainOauth
        | KeyPath::MainMtls
        | KeyPath::DedicatedOauth
        | KeyPath::DedicatedMtls
        | KeyPath::KccAccessTtl
        | KeyPath::KccRefreshTtl
        | _ => return None,
    }
    Some(())
}
