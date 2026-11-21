//! The Web-managed `[mcp]` keys, generated from one table.
//!
//! Each row names the key's dotted path below `[mcp]` and its field path, which is the
//! same in [`McpConfig`] and in [`McpOverrides`]; `opt` marks a field that is optional in
//! `kcc.toml`. The kcc.toml-only keys (`locked`, `auth.oidc.ssrf_allow_*`) have no row.

use core::{fmt, str::FromStr};

use super::document::McpOverrides;
use crate::settings::McpConfig;

/// A string that names no Web-managed `[mcp]` key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a Web-managed [mcp] key")]
#[non_exhaustive]
pub struct UnknownKey(pub String);

/// Expands the table into [`KeyPath`] and the per-key field accessors.
macro_rules! key_table {
    ($($key:ident $text:literal $mode:ident $($field:ident).+;)+) => {
        /// One Web-managed `[mcp]` key, by its dotted path below `[mcp]`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum KeyPath {
            $(
                #[doc = concat!("`", $text, "`")]
                $key,
            )+
        }

        impl KeyPath {
            /// Every key, in documentation order.
            pub const ALL: &'static [Self] = &[$(Self::$key,)+];

            /// The dotted path below `[mcp]`, as `[mcp] locked` and the state file name it.
            #[inline]
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$key => $text,)+
                }
            }

            /// Whether the key is unset unless kcc.toml or the Web sets it.
            #[inline]
            #[must_use]
            pub const fn is_optional(self) -> bool {
                match self {
                    $(Self::$key => key_table!(@optional $mode),)+
                }
            }
        }

        impl FromStr for KeyPath {
            type Err = UnknownKey;

            #[inline]
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($text => Ok(Self::$key),)+
                    _ => Err(UnknownKey(value.to_owned())),
                }
            }
        }

        /// Whether `overrides` sets `key`.
        pub(super) const fn is_set(overrides: &McpOverrides, key: KeyPath) -> bool {
            match key {
                $(KeyPath::$key => overrides.$($field).+.is_some(),)+
            }
        }

        /// Removes `key` from `overrides`.
        pub(super) fn clear(overrides: &mut McpOverrides, key: KeyPath) {
            match key {
                $(KeyPath::$key => overrides.$($field).+ = None,)+
            }
        }

        /// Copies `key` of `from` into `to`.
        pub(super) fn copy(from: &McpOverrides, key: KeyPath, to: &mut McpOverrides) {
            match key {
                $(KeyPath::$key => to.$($field).+.clone_from(&from.$($field).+),)+
            }
        }

        /// Whether `key` differs between `left` and `right`.
        pub(super) fn differs(left: &McpConfig, right: &McpConfig, key: KeyPath) -> bool {
            match key {
                $(KeyPath::$key => left.$($field).+ != right.$($field).+,)+
            }
        }

        /// Stores `key` of `overrides`, when set, into `target`.
        pub(super) fn overlay(overrides: &McpOverrides, key: KeyPath, target: &mut McpConfig) {
            match key {
                $(KeyPath::$key => {
                    if let Some(value) = &overrides.$($field).+ {
                        key_table!(@set $mode, target.$($field).+, value);
                    }
                })+
            }
        }
    };
    (@optional plain) => { false };
    (@optional opt) => { true };
    (@set plain, $($target:ident).+, $value:ident) => {
        $($target).+ = $value.clone()
    };
    (@set opt, $($target:ident).+, $value:ident) => {
        $($target).+ = Some($value.clone())
    };
}

key_table! {
    HttpEnabled "http_enabled" plain http_enabled;
    StdioEnabled "stdio_enabled" plain stdio_enabled;
    StdioRole "stdio_role" plain stdio_role;
    ReadOnly "read_only" plain read_only;
    AllowDestructive "allow_destructive" plain allow_destructive;
    MaxResultBytes "max_result_bytes" plain max_result_bytes;
    Toolsets "toolsets" plain toolsets;
    Endpoint "endpoint" plain endpoint;
    DedicatedEnabled "dedicated.enabled" plain dedicated.enabled;
    DedicatedBind "dedicated.bind" plain dedicated.bind;
    DedicatedPort "dedicated.port" plain dedicated.port;
    DedicatedPublicUrl "dedicated.public_url" opt dedicated.public_url;
    DedicatedTls "dedicated.tls" plain dedicated.tls;
    MainOauth "auth.main.oauth" plain auth.main.oauth;
    MainMtls "auth.main.mtls" plain auth.main.mtls;
    DedicatedOauth "auth.dedicated.oauth" plain auth.dedicated.oauth;
    DedicatedMtls "auth.dedicated.mtls" plain auth.dedicated.mtls;
    KccAccessTtl "auth.kcc.access_ttl" plain auth.kcc.access_ttl;
    KccRefreshTtl "auth.kcc.refresh_ttl" plain auth.kcc.refresh_ttl;
    OidcIssuer "auth.oidc.issuer" opt auth.oidc.issuer;
    OidcAudience "auth.oidc.audience" opt auth.oidc.audience;
    OidcJwksUri "auth.oidc.jwks_uri" opt auth.oidc.jwks_uri;
    OidcRoleClaim "auth.oidc.role_claim" opt auth.oidc.role_claim;
    OidcRoleMappings "auth.oidc.role_mappings" plain auth.oidc.role_mappings;
    OidcScopes "auth.oidc.scopes" plain auth.oidc.scopes;
    OidcAllowedAlgorithms "auth.oidc.allowed_algorithms" plain auth.oidc.allowed_algorithms;
    MtlsDefaultRole "auth.mtls.default_role" opt auth.mtls.default_role;
}

impl fmt::Display for KeyPath {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
