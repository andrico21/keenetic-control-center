//! The `kcc.toml` schema: loading, validation and environment overrides.
//!
//! Every struct rejects unknown keys, so a misspelled table such as `[serverr]`
//! or key such as `[web] enabeld` is an error naming it, never a silent default.
//!
//! Environment overrides: the kit sections `[server]` and `[observability]` use
//! the kit's own `RMCP_SERVER_KIT__*` variables; every other section uses the
//! `KCC_<SECTION>_<FIELD>` variables listed in [`KCC_ENV_VARS`]. List values
//! are comma-separated. `[[routers]]` has no environment overrides.

extern crate alloc;

use alloc::collections::BTreeSet;
use core::time::Duration;
use std::{
    env::{self, VarError},
    fs, io,
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use rmcp_server_kit::{
    RmcpServerKitError,
    config::{
        EnvOverride, EnvOverrideSource, ObservabilityConfig, ServerConfig,
        validate_observability_config, validate_server_config,
    },
};
use serde::Deserialize;
use toml::de::Error as TomlError;
use url::Url;

/// Every `KCC_*` environment variable [`Config::apply_env_overrides`] reads.
pub const KCC_ENV_VARS: &[&str] = &[
    "KCC_WEB_ENABLED",
    "KCC_WEB_SESSION_IDLE",
    "KCC_WEB_SESSION_ABSOLUTE",
    "KCC_WEB_LOGIN_MAX_FAILURES",
    "KCC_WEB_LOCKOUT",
    "KCC_WEB_DEFAULT_LOCALE",
    "KCC_WEB_PUBLIC_URL",
    "KCC_MCP_HTTP_ENABLED",
    "KCC_MCP_STDIO_ENABLED",
    "KCC_MCP_READ_ONLY",
    "KCC_MCP_ALLOW_DESTRUCTIVE",
    "KCC_MCP_MAX_RESULT_BYTES",
    "KCC_OUTBOUND_ALLOWED_NETWORKS",
    "KCC_OUTBOUND_ALLOWED_SUFFIXES",
    "KCC_OUTBOUND_ALLOW_LOOPBACK",
    "KCC_STATE_DIR",
    "KCC_BACKUPS_KEEP_LAST",
    "KCC_BACKUPS_MAX_AGE",
    "KCC_AUDIT_RETENTION",
    "KCC_CLI_ROLE",
    "KCC_CLI_ROUTER_SCOPE",
    "KCC_PRIVACY_REDACT_CLIENTS_IN_MCP",
];

/// Directory name used under the platform state and config directories.
const APP_DIR: &str = "kcc";

/// Error loading, overriding or validating the configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// File that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The TOML is malformed or contains an unknown table or key.
    #[error("invalid config: {0}")]
    Parse(Box<TomlError>),
    /// A kit section failed its own override or validation step.
    #[error(transparent)]
    Kit(Box<RmcpServerKitError>),
    /// A `KCC_*` environment variable holds an unusable value.
    #[error("environment variable {var}: {reason}")]
    Env {
        /// Variable name.
        var: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// A field holds a value that parses but is not allowed.
    #[error("invalid value for {field}: {reason}")]
    Invalid {
        /// Dotted path of the offending field.
        field: String,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// `[state] dir` is unset and the platform has no default state directory.
    #[error("no [state] dir configured and no platform state directory is known")]
    NoStateDir,
}

impl From<TomlError> for ConfigError {
    #[inline]
    fn from(error: TomlError) -> Self {
        Self::Parse(Box::new(error))
    }
}

impl From<RmcpServerKitError> for ConfigError {
    #[inline]
    fn from(error: RmcpServerKitError) -> Self {
        Self::Kit(Box::new(error))
    }
}

/// Root of `kcc.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Config {
    /// `[server]`: the kit's HTTP listener section.
    pub server: ServerConfig,
    /// `[observability]`: the kit's logging and metrics section.
    pub observability: ObservabilityConfig,
    /// `[web]`: Web UI settings.
    pub web: WebConfig,
    /// `[mcp]`: MCP server settings.
    pub mcp: McpConfig,
    /// `[outbound]`: which router addresses may be contacted.
    pub outbound: OutboundConfig,
    /// `[state]`: where the state store lives.
    pub state: StateConfig,
    /// `[backups]`: router config backup retention.
    pub backups: BackupsConfig,
    /// `[audit]`: audit log retention.
    pub audit: AuditConfig,
    /// `[cli]`: identity of ad-hoc CLI runs.
    pub cli: CliConfig,
    /// `[privacy]`: data minimization switches.
    pub privacy: PrivacyConfig,
    /// `[[routers]]`: config-defined router profiles (read-only in the UI).
    pub routers: Vec<RouterProfile>,
}

/// `[web]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct WebConfig {
    /// Serve the Web UI.
    pub enabled: bool,
    /// Session ends after this much inactivity.
    #[serde(with = "humantime_serde")]
    pub session_idle: Duration,
    /// Session ends this long after login regardless of activity.
    #[serde(with = "humantime_serde")]
    pub session_absolute: Duration,
    /// Failed logins before the account is locked.
    pub login_max_failures: u32,
    /// How long a locked account stays locked.
    #[serde(with = "humantime_serde")]
    pub lockout: Duration,
    /// Locale for users who have not chosen one.
    pub default_locale: String,
    /// Externally reachable base URL, when behind a proxy.
    pub public_url: Option<Url>,
}

impl Default for WebConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: true,
            session_idle: Duration::from_mins(30),
            session_absolute: Duration::from_hours(12),
            login_max_failures: 5,
            lockout: Duration::from_mins(15),
            default_locale: "en".to_owned(),
            public_url: None,
        }
    }
}

/// `[mcp]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "flat TOML schema with independent on/off switches"
)]
pub struct McpConfig {
    /// Serve MCP over Streamable HTTP.
    pub http_enabled: bool,
    /// Allow `kcc mcp stdio`.
    pub stdio_enabled: bool,
    /// Register only read tools.
    pub read_only: bool,
    /// Allow destructive tools (they still need `confirm: true`).
    pub allow_destructive: bool,
    /// Cap on the JSON text of one tool result, in bytes.
    pub max_result_bytes: u32,
}

impl Default for McpConfig {
    #[inline]
    fn default() -> Self {
        Self {
            http_enabled: true,
            stdio_enabled: false,
            read_only: false,
            allow_destructive: false,
            max_result_bytes: 32 * 1024,
        }
    }
}

/// `[outbound]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct OutboundConfig {
    /// Networks router addresses must fall into.
    pub allowed_networks: Vec<IpNet>,
    /// Host name suffixes routers may be addressed by.
    pub allowed_suffixes: Vec<String>,
    /// Allow loopback router addresses (test setups).
    pub allow_loopback: bool,
}

/// `[state]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct StateConfig {
    /// State directory; the platform default when unset.
    pub dir: Option<PathBuf>,
}

impl StateConfig {
    /// The configured state directory, or the platform default.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoStateDir`] when unset and the platform has no default.
    #[inline]
    pub fn resolved_dir(&self) -> Result<PathBuf, ConfigError> {
        self.dir
            .clone()
            .or_else(default_state_dir)
            .ok_or(ConfigError::NoStateDir)
    }
}

/// `[backups]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct BackupsConfig {
    /// Backups kept per router.
    pub keep_last: u32,
    /// Backups older than this are pruned.
    #[serde(with = "humantime_serde")]
    pub max_age: Duration,
}

impl Default for BackupsConfig {
    #[inline]
    fn default() -> Self {
        Self {
            keep_last: 50,
            max_age: Duration::from_hours(180 * 24),
        }
    }
}

/// `[audit]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct AuditConfig {
    /// Audit entries older than this are pruned.
    #[serde(with = "humantime_serde")]
    pub retention: Duration,
}

impl Default for AuditConfig {
    #[inline]
    fn default() -> Self {
        Self {
            retention: Duration::from_hours(365 * 24),
        }
    }
}

/// `[cli]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct CliConfig {
    /// Role ad-hoc CLI runs act as.
    pub role: String,
    /// Router name globs the CLI may touch; empty means all.
    pub router_scope: Vec<String>,
}

impl Default for CliConfig {
    #[inline]
    fn default() -> Self {
        Self {
            role: "admin".to_owned(),
            router_scope: Vec::new(),
        }
    }
}

/// `[privacy]` section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct PrivacyConfig {
    /// Pseudonymize client MACs, host names and addresses in MCP results.
    pub redact_clients_in_mcp: bool,
}

/// One `[[routers]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RouterProfile {
    /// Profile id, `[A-Za-z0-9._-]`, 1..=64 characters.
    pub name: String,
    /// Router base URL (`http` or `https`).
    pub url: Url,
    /// Login name; required unless `auth = "token"`.
    pub login: Option<String>,
    /// File holding the password.
    pub password_file: Option<PathBuf>,
    /// File holding the API token.
    pub token_file: Option<PathBuf>,
    /// Authentication scheme.
    #[serde(default)]
    pub auth: RouterAuth,
    /// TLS server verification.
    #[serde(default)]
    pub tls: RouterTls,
    /// Live tests may run against this router.
    #[serde(default)]
    pub test_device: bool,
    /// Free-form labels.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `auth` of a router profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RouterAuth {
    /// Pick from the router's `WWW-Authenticate` challenge.
    #[default]
    Auto,
    /// `x-ndw2-interactive`.
    Ndw2,
    /// `x-ndw4-interactive`.
    Ndw4,
    /// API token.
    Token,
    /// HTTP digest.
    Digest,
}

/// `tls` of a router profile: `"verify"` or `{ pin_sha256 = "<hex>" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouterTls {
    /// Verify the certificate chain against the system roots.
    #[default]
    Verify,
    /// Accept exactly the certificate with this SHA-256 (64 hex digits).
    PinSha256(String),
}

/// One applied environment override, for the startup report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverrideReport {
    /// Environment variable that supplied the value.
    pub env_var: String,
    /// Dotted config path that was overridden.
    pub target_field: String,
    /// The value came from the file a `*_FILE` variable names.
    pub from_file: bool,
    /// Applied value; `None` for secrets.
    pub value: Option<String>,
}

impl OverrideReport {
    /// Converts a kit override entry.
    fn from_kit(entry: EnvOverride) -> Self {
        Self {
            from_file: matches!(entry.source, EnvOverrideSource::File),
            env_var: entry.env_var,
            target_field: entry.target_field,
            value: entry.value,
        }
    }
}

impl Config {
    /// Parses `kcc.toml` text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] for malformed TOML, a wrong type, or any unknown
    /// table or key (the message names it).
    #[inline]
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(text)?)
    }

    /// Reads and parses a `kcc.toml` file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] when the file cannot be read, otherwise as
    /// [`Self::from_toml_str`].
    #[inline]
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Applies kit (`RMCP_SERVER_KIT__*`) and `KCC_*` environment overrides
    /// from the process environment and returns what was applied.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Kit`] or [`ConfigError::Env`] for an unusable value.
    #[inline]
    pub fn apply_env_overrides(&mut self) -> Result<Vec<OverrideReport>, ConfigError> {
        let mut report: Vec<OverrideReport> = self
            .server
            .apply_env_overrides()?
            .into_iter()
            .map(OverrideReport::from_kit)
            .collect();
        report.extend(
            self.observability
                .apply_env_overrides()?
                .into_iter()
                .map(OverrideReport::from_kit),
        );
        report.extend(self.apply_kcc_env_overrides_with(process_env)?);
        Ok(report)
    }

    /// Applies the `KCC_*` overrides using `lookup` as the environment.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value, or whatever `lookup` returns.
    #[inline]
    pub fn apply_kcc_env_overrides_with<F>(
        &mut self,
        lookup: F,
    ) -> Result<Vec<OverrideReport>, ConfigError>
    where
        F: Fn(&str) -> Result<Option<String>, ConfigError>,
    {
        let mut env = EnvApplier {
            lookup,
            report: Vec::new(),
        };
        env.web(&mut self.web)?;
        env.mcp(&mut self.mcp)?;
        env.outbound(&mut self.outbound)?;
        env.rest(self)?;
        Ok(env.report)
    }

    /// Checks cross-field rules serde cannot express, including the kit's own
    /// `[server]` and `[observability]` validation.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Kit`] or [`ConfigError::Invalid`] naming the field.
    #[inline]
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_server_config(&self.server)?;
        validate_observability_config(&self.observability)?;
        if self.web.login_max_failures == 0 {
            return Err(invalid("web.login_max_failures", "must be at least 1"));
        }
        if self.web.default_locale.is_empty() {
            return Err(invalid("web.default_locale", "must not be empty"));
        }
        if self.mcp.max_result_bytes == 0 {
            return Err(invalid("mcp.max_result_bytes", "must be at least 1"));
        }
        let mut names = BTreeSet::new();
        for router in &self.routers {
            router.validate()?;
            if !names.insert(router.name.as_str()) {
                return Err(invalid(
                    format!("routers.{}.name", router.name),
                    "duplicate router name",
                ));
            }
        }
        Ok(())
    }
}

impl RouterProfile {
    /// Checks one router profile.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming the field.
    fn validate(&self) -> Result<(), ConfigError> {
        let field = |key: &str| format!("routers.{}.{key}", self.name);
        if !is_valid_name(&self.name) {
            return Err(invalid(
                "routers.name",
                "must be 1..=64 characters of [A-Za-z0-9._-] not starting with '.'",
            ));
        }
        if !matches!(self.url.scheme(), "http" | "https") {
            return Err(invalid(field("url"), "scheme must be http or https"));
        }
        match (&self.password_file, &self.token_file) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(invalid(
                    field("password_file"),
                    "set exactly one of password_file and token_file",
                ));
            }
            (None, Some(_)) => {
                if !matches!(self.auth, RouterAuth::Token | RouterAuth::Auto) {
                    return Err(invalid(field("auth"), "token_file needs auth = \"token\""));
                }
            }
            (Some(_), None) => {
                if self.auth == RouterAuth::Token {
                    return Err(invalid(field("auth"), "auth = \"token\" needs token_file"));
                }
                if self.login.as_deref().is_none_or(str::is_empty) {
                    return Err(invalid(field("login"), "required with password_file"));
                }
            }
        }
        if let RouterTls::PinSha256(pin) = &self.tls
            && !(pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(invalid(field("tls.pin_sha256"), "must be 64 hex digits"));
        }
        Ok(())
    }
}

/// Platform default state directory: `$XDG_STATE_HOME/kcc` (else
/// `~/.local/state/kcc`) on Linux and other unix, `%LOCALAPPDATA%\kcc` on
/// Windows, `~/Library/Application Support/kcc` on macOS.
#[inline]
#[must_use]
pub fn default_state_dir() -> Option<PathBuf> {
    platform_base(BaseDir::State).map(|base| base.join(APP_DIR))
}

/// Platform default config directory: `$XDG_CONFIG_HOME/kcc` (else
/// `~/.config/kcc`) on Linux and other unix, `%APPDATA%\kcc` on Windows,
/// `~/Library/Application Support/kcc` on macOS.
#[inline]
#[must_use]
pub fn default_config_dir() -> Option<PathBuf> {
    platform_base(BaseDir::Config).map(|base| base.join(APP_DIR))
}

/// Which platform base directory to resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseDir {
    /// Machine-local state.
    State,
    /// User configuration.
    Config,
}

/// An absolute path from environment variable `var`.
fn env_dir(var: &str) -> Option<PathBuf> {
    env::var_os(var)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Resolves a base directory on Windows.
#[cfg(windows)]
fn platform_base(kind: BaseDir) -> Option<PathBuf> {
    match kind {
        BaseDir::State => env_dir("LOCALAPPDATA"),
        BaseDir::Config => env_dir("APPDATA"),
    }
}

/// Resolves a base directory on macOS.
#[cfg(target_os = "macos")]
fn platform_base(kind: BaseDir) -> Option<PathBuf> {
    let _: BaseDir = kind;
    env::home_dir().map(|home| home.join("Library/Application Support"))
}

/// Resolves a base directory with the XDG base directory rules.
#[cfg(not(any(windows, target_os = "macos")))]
fn platform_base(kind: BaseDir) -> Option<PathBuf> {
    let (var, fallback) = match kind {
        BaseDir::State => ("XDG_STATE_HOME", ".local/state"),
        BaseDir::Config => ("XDG_CONFIG_HOME", ".config"),
    };
    env_dir(var).or_else(|| env::home_dir().map(|home| home.join(fallback)))
}

/// Whether `name` is a safe profile or file name component.
pub(crate) fn is_valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Builds a [`ConfigError::Invalid`].
fn invalid<S>(field: S, reason: &'static str) -> ConfigError
where
    S: Into<String>,
{
    ConfigError::Invalid {
        field: field.into(),
        reason,
    }
}

/// Reads one variable from the process environment.
///
/// # Errors
///
/// [`ConfigError::Env`] when the value is not UTF-8.
fn process_env(var: &str) -> Result<Option<String>, ConfigError> {
    match env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::Env {
            var: var.to_owned(),
            reason: "not valid UTF-8".to_owned(),
        }),
    }
}

/// Applies `KCC_*` variables and records each one applied.
struct EnvApplier<F> {
    /// Environment lookup.
    lookup: F,
    /// Overrides applied so far.
    report: Vec<OverrideReport>,
}

impl<F> EnvApplier<F>
where
    F: Fn(&str) -> Result<Option<String>, ConfigError>,
{
    /// Overrides `target` from `var` when it is set.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value.
    fn apply<T, P>(
        &mut self,
        var: &'static str,
        field: &'static str,
        target: &mut T,
        parse: P,
    ) -> Result<(), ConfigError>
    where
        P: FnOnce(&str) -> Result<T, String>,
    {
        let Some(raw) = (self.lookup)(var)? else {
            return Ok(());
        };
        *target = parse(raw.trim()).map_err(|reason| ConfigError::Env {
            var: var.to_owned(),
            reason,
        })?;
        self.report.push(OverrideReport {
            env_var: var.to_owned(),
            target_field: field.to_owned(),
            from_file: false,
            value: Some(raw),
        });
        Ok(())
    }

    /// `[web]` overrides.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value.
    fn web(&mut self, web: &mut WebConfig) -> Result<(), ConfigError> {
        self.apply(
            "KCC_WEB_ENABLED",
            "web.enabled",
            &mut web.enabled,
            parse_bool,
        )?;
        self.apply(
            "KCC_WEB_SESSION_IDLE",
            "web.session_idle",
            &mut web.session_idle,
            parse_duration,
        )?;
        self.apply(
            "KCC_WEB_SESSION_ABSOLUTE",
            "web.session_absolute",
            &mut web.session_absolute,
            parse_duration,
        )?;
        self.apply(
            "KCC_WEB_LOGIN_MAX_FAILURES",
            "web.login_max_failures",
            &mut web.login_max_failures,
            parse_number,
        )?;
        self.apply(
            "KCC_WEB_LOCKOUT",
            "web.lockout",
            &mut web.lockout,
            parse_duration,
        )?;
        self.apply(
            "KCC_WEB_DEFAULT_LOCALE",
            "web.default_locale",
            &mut web.default_locale,
            parse_string,
        )?;
        self.apply(
            "KCC_WEB_PUBLIC_URL",
            "web.public_url",
            &mut web.public_url,
            |raw| Url::parse(raw).map(Some).map_err(|error| error.to_string()),
        )
    }

    /// `[mcp]` overrides.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value.
    fn mcp(&mut self, mcp: &mut McpConfig) -> Result<(), ConfigError> {
        self.apply(
            "KCC_MCP_HTTP_ENABLED",
            "mcp.http_enabled",
            &mut mcp.http_enabled,
            parse_bool,
        )?;
        self.apply(
            "KCC_MCP_STDIO_ENABLED",
            "mcp.stdio_enabled",
            &mut mcp.stdio_enabled,
            parse_bool,
        )?;
        self.apply(
            "KCC_MCP_READ_ONLY",
            "mcp.read_only",
            &mut mcp.read_only,
            parse_bool,
        )?;
        self.apply(
            "KCC_MCP_ALLOW_DESTRUCTIVE",
            "mcp.allow_destructive",
            &mut mcp.allow_destructive,
            parse_bool,
        )?;
        self.apply(
            "KCC_MCP_MAX_RESULT_BYTES",
            "mcp.max_result_bytes",
            &mut mcp.max_result_bytes,
            parse_number,
        )
    }

    /// `[outbound]` overrides.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value.
    fn outbound(&mut self, outbound: &mut OutboundConfig) -> Result<(), ConfigError> {
        self.apply(
            "KCC_OUTBOUND_ALLOWED_NETWORKS",
            "outbound.allowed_networks",
            &mut outbound.allowed_networks,
            |raw| {
                split_list(raw)
                    .into_iter()
                    .map(|item| item.parse::<IpNet>().map_err(|error| error.to_string()))
                    .collect()
            },
        )?;
        self.apply(
            "KCC_OUTBOUND_ALLOWED_SUFFIXES",
            "outbound.allowed_suffixes",
            &mut outbound.allowed_suffixes,
            |raw| Ok(split_list(raw)),
        )?;
        self.apply(
            "KCC_OUTBOUND_ALLOW_LOOPBACK",
            "outbound.allow_loopback",
            &mut outbound.allow_loopback,
            parse_bool,
        )
    }

    /// `[state]`, `[backups]`, `[audit]`, `[cli]` and `[privacy]` overrides.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Env`] for an unusable value.
    fn rest(&mut self, config: &mut Config) -> Result<(), ConfigError> {
        self.apply("KCC_STATE_DIR", "state.dir", &mut config.state.dir, |raw| {
            if raw.is_empty() {
                Err("must not be empty".to_owned())
            } else {
                Ok(Some(PathBuf::from(raw)))
            }
        })?;
        self.apply(
            "KCC_BACKUPS_KEEP_LAST",
            "backups.keep_last",
            &mut config.backups.keep_last,
            parse_number,
        )?;
        self.apply(
            "KCC_BACKUPS_MAX_AGE",
            "backups.max_age",
            &mut config.backups.max_age,
            parse_duration,
        )?;
        self.apply(
            "KCC_AUDIT_RETENTION",
            "audit.retention",
            &mut config.audit.retention,
            parse_duration,
        )?;
        self.apply(
            "KCC_CLI_ROLE",
            "cli.role",
            &mut config.cli.role,
            parse_string,
        )?;
        self.apply(
            "KCC_CLI_ROUTER_SCOPE",
            "cli.router_scope",
            &mut config.cli.router_scope,
            |raw| Ok(split_list(raw)),
        )?;
        self.apply(
            "KCC_PRIVACY_REDACT_CLIENTS_IN_MCP",
            "privacy.redact_clients_in_mcp",
            &mut config.privacy.redact_clients_in_mcp,
            parse_bool,
        )
    }
}

/// Parses `true`/`false`/`1`/`0`.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("expected true, false, 1 or 0".to_owned()),
    }
}

/// Parses a humantime duration such as `30m` or `180d`.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_duration(raw: &str) -> Result<Duration, String> {
    humantime::parse_duration(raw).map_err(|error| error.to_string())
}

/// Parses an unsigned integer.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_number(raw: &str) -> Result<u32, String> {
    raw.parse::<u32>().map_err(|error| error.to_string())
}

/// Accepts any non-empty string.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_string(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        Err("must not be empty".to_owned())
    } else {
        Ok(raw.to_owned())
    }
}

/// Splits a comma-separated list, dropping empty items.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}
