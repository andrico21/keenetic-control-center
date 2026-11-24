//! The roles a sign-in source hands out.
//!
//! The identity provider's tokens get the roles of its mappings, client certificates the
//! mTLS role. Whoever decides where such identities come from (the provider's address,
//! audience or role claim, a listener now using the source, the CA that issues or vouches
//! for them) can mint them, so that actor must cover every role the source hands out.

extern crate alloc;

use alloc::collections::BTreeSet;

use super::{
    ListenerKind,
    keys::{self, KeyPath},
};
use crate::settings::{
    McpConfig,
    mcp_schema::{ListenerAuth, MtlsMode, OauthMode},
};

/// A source of MCP identities whose roles the settings fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TrustAnchor {
    /// Client certificates under the client CA.
    ClientCa,
    /// Tokens of the external identity provider.
    IdentityProvider,
}

/// The role of a client certificate while `[mcp.auth.mtls] default_role` is unset (the
/// kit's default).
const MTLS_DEFAULT_ROLE: &str = "viewer";

/// The keys that decide whose tokens count as the identity provider's and which claim
/// picks their role.
const PROVIDER_KEYS: [KeyPath; 4] = [
    KeyPath::OidcIssuer,
    KeyPath::OidcAudience,
    KeyPath::OidcJwksUri,
    KeyPath::OidcRoleClaim,
];

/// The roles `anchor` hands out under `mcp`; none for a provider without mappings.
pub(super) fn roles(mcp: &McpConfig, anchor: TrustAnchor) -> BTreeSet<String> {
    match anchor {
        TrustAnchor::ClientCa => BTreeSet::from([mcp
            .auth
            .mtls
            .default_role
            .clone()
            .unwrap_or_else(|| MTLS_DEFAULT_ROLE.to_owned())]),
        TrustAnchor::IdentityProvider => {
            let oidc = &mcp.auth.oidc;
            oidc.role_mappings
                .iter()
                .map(|mapping| mapping.role.clone())
                .chain(oidc.scopes.iter().map(|mapping| mapping.role.clone()))
                .collect()
        }
    }
}

/// Whether going from `before` to `after` changes where `anchor`'s identities come from:
/// a listener signs in with it that did not, or (for the provider) its issuer, audience,
/// JWKS URL or role claim changed.
pub(super) fn repointed(before: &McpConfig, after: &McpConfig, anchor: TrustAnchor) -> bool {
    let newly_used = [ListenerKind::Main, ListenerKind::Dedicated]
        .into_iter()
        .any(|listener| used(after, anchor, listener) && !used(before, anchor, listener));
    newly_used
        || (anchor == TrustAnchor::IdentityProvider
            && PROVIDER_KEYS
                .iter()
                .any(|key| keys::differs(before, after, *key)))
}

/// Whether `listener` of `mcp` runs and signs in with `anchor`.
fn used(mcp: &McpConfig, anchor: TrustAnchor, listener: ListenerKind) -> bool {
    let auth: ListenerAuth = match listener {
        ListenerKind::Main => mcp.auth.main,
        ListenerKind::Dedicated if mcp.dedicated.enabled => mcp.auth.dedicated,
        ListenerKind::Dedicated => return false,
    };
    match anchor {
        TrustAnchor::ClientCa => auth.mtls != MtlsMode::Off,
        TrustAnchor::IdentityProvider => auth.oauth == OauthMode::External,
    }
}
