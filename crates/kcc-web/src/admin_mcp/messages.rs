//! The localized words of the page: key labels and sources, and the messages of refused
//! and reverted changes. A refusal shows a class only, never an error's own text.

use fluent_bundle::FluentArgs;
use kcc_app::{
    mcp_settings::{ListenerKind, SettingsError, Source, keys::KeyPath},
    settings::ConfigError,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::form::FormError;
use crate::admin::mcp_control::McpRefusal;

/// The label of `key`.
pub(crate) const fn label(key: KeyPath) -> MessageKey {
    match key {
        KeyPath::HttpEnabled => keys::WEB_ADMIN_MCP_KEY_HTTP_ENABLED,
        KeyPath::StdioEnabled => keys::WEB_ADMIN_MCP_KEY_STDIO_ENABLED,
        KeyPath::StdioRole => keys::WEB_ADMIN_MCP_KEY_STDIO_ROLE,
        KeyPath::ReadOnly => keys::WEB_ADMIN_MCP_KEY_READ_ONLY,
        KeyPath::AllowDestructive => keys::WEB_ADMIN_MCP_KEY_ALLOW_DESTRUCTIVE,
        KeyPath::MaxResultBytes => keys::WEB_ADMIN_MCP_KEY_MAX_RESULT_BYTES,
        KeyPath::Toolsets => keys::WEB_ADMIN_MCP_KEY_TOOLSETS,
        KeyPath::Endpoint => keys::WEB_ADMIN_MCP_KEY_ENDPOINT,
        KeyPath::DedicatedEnabled => keys::WEB_ADMIN_MCP_KEY_DEDICATED_ENABLED,
        KeyPath::DedicatedBind => keys::WEB_ADMIN_MCP_KEY_DEDICATED_BIND,
        KeyPath::DedicatedPort => keys::WEB_ADMIN_MCP_KEY_DEDICATED_PORT,
        KeyPath::DedicatedPublicUrl => keys::WEB_ADMIN_MCP_KEY_DEDICATED_PUBLIC_URL,
        KeyPath::DedicatedTls => keys::WEB_ADMIN_MCP_KEY_DEDICATED_TLS,
        KeyPath::MainOauth => keys::WEB_ADMIN_MCP_KEY_MAIN_OAUTH,
        KeyPath::MainMtls => keys::WEB_ADMIN_MCP_KEY_MAIN_MTLS,
        KeyPath::DedicatedOauth => keys::WEB_ADMIN_MCP_KEY_DEDICATED_OAUTH,
        KeyPath::DedicatedMtls => keys::WEB_ADMIN_MCP_KEY_DEDICATED_MTLS,
        KeyPath::KccAccessTtl => keys::WEB_ADMIN_MCP_KEY_ACCESS_TTL,
        KeyPath::KccRefreshTtl => keys::WEB_ADMIN_MCP_KEY_REFRESH_TTL,
        KeyPath::OidcIssuer => keys::WEB_ADMIN_MCP_KEY_OIDC_ISSUER,
        KeyPath::OidcAudience => keys::WEB_ADMIN_MCP_KEY_OIDC_AUDIENCE,
        KeyPath::OidcJwksUri => keys::WEB_ADMIN_MCP_KEY_OIDC_JWKS_URI,
        KeyPath::OidcRoleClaim => keys::WEB_ADMIN_MCP_KEY_OIDC_ROLE_CLAIM,
        KeyPath::OidcRoleMappings => keys::WEB_ADMIN_MCP_KEY_OIDC_ROLE_MAPPINGS,
        KeyPath::OidcScopes => keys::WEB_ADMIN_MCP_KEY_OIDC_SCOPES,
        KeyPath::OidcAllowedAlgorithms => keys::WEB_ADMIN_MCP_KEY_OIDC_ALGORITHMS,
        KeyPath::MtlsDefaultRole | _ => keys::WEB_ADMIN_MCP_KEY_MTLS_DEFAULT_ROLE,
    }
}

/// The words of `source`.
pub(crate) const fn source(source: Source) -> MessageKey {
    match source {
        Source::Env => keys::WEB_ADMIN_MCP_SOURCE_ENV,
        Source::Locked => keys::WEB_ADMIN_MCP_SOURCE_LOCKED,
        Source::State => keys::WEB_ADMIN_MCP_SOURCE_STATE,
        Source::Toml => keys::WEB_ADMIN_MCP_SOURCE_TOML,
        Source::Default | _ => keys::WEB_ADMIN_MCP_SOURCE_DEFAULT,
    }
}

/// The name of `kind` inside a message.
pub(crate) const fn listener(kind: ListenerKind) -> MessageKey {
    match kind {
        ListenerKind::Main => keys::WEB_ADMIN_MCP_LISTENER_MAIN,
        ListenerKind::Dedicated | _ => keys::WEB_ADMIN_MCP_LISTENER_DEDICATED,
    }
}

/// A localized message with its key, for the `data-message-key` of its notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Said {
    /// The message's key.
    key: MessageKey,
    /// The message in the page's locale.
    text: String,
}

impl Said {
    /// `key` in `locale` with the one argument `(name, value)`, if any.
    pub(crate) fn new(
        locale: Locale,
        key: MessageKey,
        arg: Option<(&'static str, String)>,
    ) -> Self {
        let mut args = FluentArgs::new();
        if let Some((name, value)) = arg {
            args.set(name, value);
        }
        Self {
            key,
            text: tr(locale, key, Some(&args)),
        }
    }

    /// `key` in `locale` naming the key `what` by its label.
    fn about(locale: Locale, key: MessageKey, what: KeyPath) -> Self {
        Self::new(locale, key, Some(("what", tr(locale, label(what), None))))
    }

    /// The message's key name.
    pub(crate) const fn key(&self) -> &'static str {
        self.key.id()
    }

    /// The message.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Why the form was refused.
    pub(crate) fn form(locale: Locale, error: FormError) -> Self {
        match error {
            FormError::UnknownField => Self::new(locale, keys::WEB_ADMIN_MCP_ERROR_FIELDS, None),
            FormError::Value(key) => Self::about(locale, keys::WEB_ADMIN_MCP_ERROR_VALUE, key),
            FormError::Env(key) => Self::about(locale, keys::WEB_ADMIN_MCP_ERROR_ENV, key),
            FormError::Locked(key) => Self::about(locale, keys::WEB_ADMIN_MCP_ERROR_LOCKED, key),
        }
    }

    /// Why planning the change was refused; `None` for a failure of the state itself.
    pub(crate) fn plan(locale: Locale, error: &SettingsError) -> Option<Self> {
        let named = |key, name: &String| Self::new(locale, key, Some(("value", name.clone())));
        Some(match error {
            SettingsError::EnvSet { key } => {
                Self::about(locale, keys::WEB_ADMIN_MCP_ERROR_ENV, *key)
            }
            SettingsError::Locked { key } => {
                Self::about(locale, keys::WEB_ADMIN_MCP_ERROR_LOCKED, *key)
            }
            SettingsError::UnknownToolset { name } => {
                named(keys::WEB_ADMIN_MCP_ERROR_TOOLSET, name)
            }
            SettingsError::UnknownRole { name } => {
                named(keys::WEB_ADMIN_MCP_ERROR_ROLE_UNKNOWN, name)
            }
            SettingsError::RoleAbove { name } => named(keys::WEB_ADMIN_MCP_ERROR_ROLE_ABOVE, name),
            SettingsError::ProviderAbove { name } => {
                named(keys::WEB_ADMIN_MCP_OIDC_ROLE_ABOVE, name)
            }
            SettingsError::CertificatesAbove { name } => {
                named(keys::WEB_ADMIN_MCP_MTLS_ROLE_ABOVE, name)
            }
            SettingsError::ActorRevoked { name: _ } => {
                Self::new(locale, keys::WEB_ADMIN_MCP_ERROR_ACTOR, None)
            }
            SettingsError::SettingsChanged | SettingsError::RevisionExhausted => {
                Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_SETTINGS_CHANGED, None)
            }
            SettingsError::Invalid(ConfigError::Invalid { field, reason: _ }) => {
                let what = field
                    .strip_prefix("mcp.")
                    .and_then(|path| path.parse::<KeyPath>().ok())
                    .map_or_else(|| field.clone(), |key| tr(locale, label(key), None));
                Self::new(
                    locale,
                    keys::WEB_ADMIN_MCP_ERROR_INVALID,
                    Some(("what", what)),
                )
            }
            SettingsError::State(_) | SettingsError::Roles(_) | SettingsError::Invalid(_) | _ => {
                return None;
            }
        })
    }

    /// Why the listeners did not apply a change.
    pub(crate) fn refusal(locale: Locale, refusal: McpRefusal) -> Self {
        let on = |key, kind| {
            Self::new(
                locale,
                key,
                Some(("what", tr(locale, listener(kind), None))),
            )
        };
        match refusal {
            McpRefusal::SettingsChanged => {
                Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_SETTINGS_CHANGED, None)
            }
            McpRefusal::SignInUnavailable(kind) => {
                on(keys::WEB_ADMIN_MCP_RESTART_SIGN_IN_UNAVAILABLE, kind)
            }
            McpRefusal::Unusable(kind) => on(keys::WEB_ADMIN_MCP_RESTART_UNUSABLE, kind),
            McpRefusal::Bind(kind) => on(keys::WEB_ADMIN_MCP_RESTART_BIND, kind),
            McpRefusal::Serve(kind) => on(keys::WEB_ADMIN_MCP_RESTART_SERVE, kind),
            McpRefusal::Register(kind) => on(keys::WEB_ADMIN_MCP_RESTART_REGISTER, kind),
            McpRefusal::Health(kind) => on(keys::WEB_ADMIN_MCP_RESTART_HEALTH, kind),
            McpRefusal::Apply => Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_APPLY, None),
            McpRefusal::Commit => Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_COMMIT, None),
            McpRefusal::ShuttingDown => {
                Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_STOPPING, None)
            }
            McpRefusal::Failed => Self::new(locale, keys::WEB_ADMIN_MCP_RESTART_FAILED, None),
            McpRefusal::ConfirmationRequired => {
                Self::new(locale, keys::WEB_ADMIN_MCP_MTLS_CA_PASSWORD, None)
            }
        }
    }
}
