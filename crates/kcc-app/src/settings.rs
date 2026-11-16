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
use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::{
    env, fs, io,
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
use serde::{Deserialize, Serialize};
use toml::de::Error as TomlError;
use url::Url;

mod env_overrides;

/// Every `KCC_*` environment variable [`Config::apply_env_overrides`] reads.
pub const KCC_ENV_VARS: &[&str] = env_overrides::NAMES;

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
    /// `[metrics]`: the Prometheus exporter.
    pub metrics: MetricsConfig,
    /// `[logs]`: router log collection and forwarding.
    pub logs: LogsConfig,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
    /// Application role assigned to the fixed local `stdio` identity.
    pub stdio_role: String,
    /// Register only read tools.
    pub read_only: bool,
    /// Allow destructive tools (they still need `confirm: true`).
    pub allow_destructive: bool,
    /// Cap on the JSON text of one tool result, in bytes.
    pub max_result_bytes: u32,
    /// Tool groups registered by the MCP server.
    pub toolsets: Vec<String>,
}

impl Default for McpConfig {
    #[inline]
    fn default() -> Self {
        Self {
            http_enabled: true,
            stdio_enabled: false,
            stdio_role: "viewer".to_owned(),
            read_only: false,
            allow_destructive: false,
            max_result_bytes: 32 * 1024,
            toolsets: vec!["core".to_owned()],
        }
    }
}

/// `[outbound]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
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
    /// Maximum age of complete rotated audit files. When the active file rotates, the
    /// oldest rotated files whose newest entry is older than this are deleted whole; the
    /// active file is never pruned, and nothing is pruned between rotations.
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

/// Shortest allowed `[metrics] interval` (IS-13 light cadence floor).
pub const METRICS_MIN_INTERVAL: Duration = Duration::from_secs(15);
/// Shortest allowed `[metrics] heavy_interval` (IS-13 heavy cadence floor).
pub const METRICS_MIN_HEAVY_INTERVAL: Duration = Duration::from_secs(60);

/// `[metrics]` section: the Prometheus exporter.
///
/// The exporter listener is plaintext and unauthenticated by design (the kit's `/metrics`
/// listener), so it binds loopback unless `allow_non_loopback = true`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct MetricsConfig {
    /// Serve `/metrics`.
    pub enabled: bool,
    /// Listener address of the unauthenticated `/metrics` endpoint.
    pub bind: SocketAddr,
    /// Permit a non-loopback `bind`.
    pub allow_non_loopback: bool,
    /// Light-item refresh period of the shared poller's metrics subscription.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Heavy-item refresh period of the shared poller's metrics subscription.
    #[serde(with = "humantime_serde")]
    pub heavy_interval: Duration,
    /// Export per-client series.
    pub per_client: bool,
    /// Per-router cap on exported clients; overflow is counted, not exported.
    pub per_client_max: u32,
    /// How clients are labelled in per-client series.
    pub per_client_label: ClientLabel,
}

impl Default for MetricsConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: false,
            bind: SocketAddr::from(([127, 0, 0, 1], 9090)),
            allow_non_loopback: false,
            interval: Duration::from_secs(30),
            heavy_interval: Duration::from_secs(120),
            per_client: false,
            per_client_max: 256,
            per_client_label: ClientLabel::Pseudonym,
        }
    }
}

impl MetricsConfig {
    /// Checks the IS-13 cadence floors, the listener port and the loopback rule.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming the field.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.interval < METRICS_MIN_INTERVAL {
            return Err(invalid("metrics.interval", "must be at least 15s"));
        }
        if self.heavy_interval < METRICS_MIN_HEAVY_INTERVAL || self.heavy_interval < self.interval {
            return Err(invalid(
                "metrics.heavy_interval",
                "must be at least 60s and at least metrics.interval",
            ));
        }
        if self.bind.port() < 1024 {
            return Err(invalid(
                "metrics.bind",
                "port must be at least 1024; this service never binds privileged ports",
            ));
        }
        if !self.bind.ip().is_loopback() && !self.allow_non_loopback {
            return Err(invalid(
                "metrics.bind",
                "the metrics listener is unauthenticated; a non-loopback bind needs allow_non_loopback = true",
            ));
        }
        if self.per_client_max == 0 {
            return Err(invalid("metrics.per_client_max", "must be at least 1"));
        }
        Ok(())
    }
}

/// `per_client_label` of `[metrics]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ClientLabel {
    /// The router's client name.
    Name,
    /// A stable per-process pseudonym.
    #[default]
    Pseudonym,
    /// The raw MAC address.
    Mac,
}

/// Shortest allowed interval between background log-stream polls.
pub const LOG_STREAM_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Shortest allowed interval between snapshot log polls.
pub const LOG_POLL_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Default maximum number of pending records retained by each log sink.
pub const LOG_QUEUE_MAX: usize = 10_000;

/// `[logs]` section: router log collection and forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct LogsConfig {
    /// Collect router logs.
    pub enabled: bool,
    /// Router profile ids to collect; empty selects every router.
    pub routers: Vec<String>,
    /// Preferred collection mechanism.
    pub mode: LogMode,
    /// Delay between reads from a background stream.
    #[serde(with = "humantime_serde")]
    pub stream_interval: Duration,
    /// Delay between one-shot snapshot reads.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Replace MAC addresses in messages before fan-out.
    pub redact_macs: bool,
    /// Maximum pending records retained independently for each sink.
    pub queue_max: usize,
    /// Forwarding destinations.
    pub sinks: Vec<LogSinkConfig>,
}

impl Default for LogsConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: false,
            routers: Vec::new(),
            mode: LogMode::Stream,
            stream_interval: LOG_STREAM_MIN_INTERVAL,
            poll_interval: Duration::from_secs(30),
            redact_macs: false,
            queue_max: LOG_QUEUE_MAX,
            sinks: Vec::new(),
        }
    }
}

impl LogsConfig {
    /// Checks cadence floors, router ids, and sink transport settings.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming the rejected field.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.stream_interval < LOG_STREAM_MIN_INTERVAL {
            return Err(invalid("logs.stream_interval", "must be at least 5s"));
        }
        if self.poll_interval < LOG_POLL_MIN_INTERVAL {
            return Err(invalid("logs.poll_interval", "must be at least 5s"));
        }
        if self
            .routers
            .iter()
            .any(|router| !is_valid_router_id(router))
        {
            return Err(invalid(
                "logs.routers",
                "every router must be a valid profile id",
            ));
        }
        if self.queue_max == 0 {
            return Err(invalid("logs.queue_max", "must be at least 1"));
        }
        for (index, sink) in self.sinks.iter().enumerate() {
            sink.validate(index)?;
        }
        Ok(())
    }
}

/// Router log collection mechanism.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum LogMode {
    /// Prefer a background stream and fall back after repeated start failures.
    #[default]
    Stream,
    /// Read bounded snapshots periodically.
    Poll,
}

/// One `[[logs.sinks]]` destination.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
#[non_exhaustive]
pub enum LogSinkConfig {
    /// Grafana Loki push endpoint.
    Loki {
        /// Base URL; the collector appends `/loki/api/v1/push`.
        url: Url,
        /// Optional Loki tenant header.
        tenant: Option<String>,
        /// Optional HTTP Basic user.
        basic_auth_user: Option<String>,
        /// File containing the HTTP Basic password.
        password_file: Option<PathBuf>,
        /// File containing a bearer token.
        bearer_token_file: Option<PathBuf>,
        /// PEM CA certificate file.
        ca_file: Option<PathBuf>,
        /// Compress request bodies with gzip.
        #[serde(default)]
        compress: bool,
    },
    /// Elasticsearch or `OpenSearch` bulk endpoint.
    Elasticsearch {
        /// Base URL; the collector appends `/_bulk`.
        url: Url,
        /// Bulk API flavor.
        #[serde(default)]
        flavor: SearchFlavor,
        /// Optional target override.
        target: Option<String>,
        /// Optional HTTP Basic user.
        basic_auth_user: Option<String>,
        /// File containing the HTTP Basic password.
        password_file: Option<PathBuf>,
        /// File containing an Elasticsearch/OpenSearch API key.
        api_key_file: Option<PathBuf>,
        /// PEM CA certificate file.
        ca_file: Option<PathBuf>,
        /// Compress request bodies with gzip.
        #[serde(default)]
        compress: bool,
    },
    /// One JSON object per line on standard output.
    Stdout,
}

impl LogSinkConfig {
    /// Checks one sink boundary.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming the rejected sink field.
    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        let (url, user, password, token, auth_reason) = match self {
            Self::Loki {
                url,
                basic_auth_user,
                password_file,
                bearer_token_file,
                tenant: _,
                ca_file: _,
                compress: _,
            } => (
                url,
                basic_auth_user,
                password_file,
                bearer_token_file,
                "set basic_auth_user with password_file, or bearer_token_file, or neither",
            ),
            Self::Elasticsearch {
                url,
                basic_auth_user,
                password_file,
                api_key_file,
                flavor: _,
                target: _,
                ca_file: _,
                compress: _,
            } => (
                url,
                basic_auth_user,
                password_file,
                api_key_file,
                "set basic_auth_user with password_file, or api_key_file, or neither",
            ),
            Self::Stdout => return Ok(()),
        };
        let field = |name: &str| format!("logs.sinks.{index}.{name}");
        let loopback = match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(invalid(
                field("url"),
                "must use https; http is accepted only for a loopback test sink",
            ));
        }
        if url.cannot_be_a_base()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid(
                field("url"),
                "must be a base URL without credentials, query, or fragment",
            ));
        }
        match (user, password, token) {
            (Some(name), Some(_), None) if !name.is_empty() => Ok(()),
            (None, None, Some(_) | None) => Ok(()),
            _ => Err(invalid(field("password_file"), auth_reason)),
        }
    }
}

/// Bulk API dialect used by an Elasticsearch sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SearchFlavor {
    /// Elasticsearch data-stream defaults.
    #[default]
    Elasticsearch,
    /// `OpenSearch` dated-index defaults.
    Opensearch,
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
    /// Optional login used by the shared read-only poller.
    #[serde(default)]
    pub read_login: Option<String>,
    /// Optional password file used by the shared read-only poller.
    #[serde(default)]
    pub read_password_file: Option<PathBuf>,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
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

impl RouterAuth {
    /// Whether the scheme is picked from the router's challenge (the default).
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's skip_serializing_if passes the field by reference"
    )]
    #[inline]
    #[must_use]
    pub const fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

/// `tls` of a router profile: `"verify"` or `{ pin_sha256 = "<hex>" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
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
    /// Whether the listener itself terminates TLS: a certificate and a key are both set.
    #[inline]
    #[must_use]
    pub const fn listener_tls(&self) -> bool {
        self.server.tls_cert_path.is_some() && self.server.tls_key_path.is_some()
    }

    /// Whether the browser reaches kcc over TLS: the listener has TLS, or `web.public_url`
    /// is an `https` URL (an HTTPS reverse proxy in front of a plain listener). The Web
    /// session cookie and the content security policy follow this one decision.
    #[inline]
    #[must_use]
    pub fn browser_transport_secure(&self) -> bool {
        self.listener_tls()
            || self
                .web
                .public_url
                .as_ref()
                .is_some_and(|url| url.scheme() == "https")
    }

    /// Parses `kcc.toml` text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] for malformed TOML, a wrong type, or any unknown
    /// table or key (the message names it).
    #[inline]
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let mut config = toml::from_str::<Self>(text)?;
        normalize_suffixes(&mut config.outbound.allowed_suffixes)?;
        Ok(config)
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
        report.extend(self.apply_kcc_env_overrides_with(env_overrides::process_env)?);
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
        env_overrides::apply(self, lookup)
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
        if self.server.listen_port < 1024 {
            return Err(invalid(
                "server.listen_port",
                "must be at least 1024; this service never binds privileged ports",
            ));
        }
        if self.observability.metrics_enabled {
            let metrics_addr = self
                .observability
                .metrics_bind
                .parse::<SocketAddr>()
                .map_err(|_error| {
                    invalid(
                        "observability.metrics_bind",
                        "must be a socket address such as 127.0.0.1:9090",
                    )
                })?;
            if metrics_addr.port() < 1024 {
                return Err(invalid(
                    "observability.metrics_bind",
                    "port must be at least 1024; this service never binds privileged ports",
                ));
            }
        }
        self.metrics.validate()?;
        self.logs.validate()?;
        if self.metrics.enabled && self.observability.metrics_enabled {
            return Err(invalid(
                "observability.metrics_enabled",
                "conflicts with [metrics] enabled; configure the exporter in [metrics] only",
            ));
        }
        if self.web.login_max_failures == 0 {
            return Err(invalid("web.login_max_failures", "must be at least 1"));
        }
        if self.web.default_locale.is_empty() {
            return Err(invalid("web.default_locale", "must not be empty"));
        }
        drop(self.web_allowed_origins()?);
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

    /// Derives the Web UI Origin allowlist from its public URL and listener.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] when Web UI transport settings would
    /// expose plain HTTP beyond loopback, trust an undeclared reverse proxy, or
    /// produce no origin accepted by the shared HTTP transport.
    #[inline]
    pub fn web_allowed_origins(&self) -> Result<Vec<String>, ConfigError> {
        if !self.web.enabled {
            return Ok(Vec::new());
        }
        let listen_text = self.server.listen_addr.trim_matches(['[', ']']);
        let listen_ip = listen_text.parse::<IpAddr>().map_err(|_error| {
            invalid("server.listen_addr", "must be an IP address for the Web UI")
        })?;
        let tls = self.listener_tls();
        let trusted_https_proxy =
            self.browser_transport_secure() && !self.server.trusted_proxies.is_empty();
        if !(listen_ip.is_loopback() || tls || trusted_https_proxy) {
            return Err(invalid(
                "server.listen_addr",
                "a non-loopback Web UI requires TLS or an https web.public_url behind trusted_proxies",
            ));
        }
        if self.web.public_url.is_some() && self.server.trusted_proxies.is_empty() && !tls {
            return Err(invalid(
                "server.trusted_proxies",
                "web.public_url without listener TLS requires at least one trusted proxy",
            ));
        }

        let mut origins = BTreeSet::new();
        if let Some(public_url) = &self.web.public_url {
            if !matches!(public_url.scheme(), "http" | "https") {
                return Err(invalid("web.public_url", "scheme must be http or https"));
            }
            let _: bool = origins.insert(public_url.origin().ascii_serialization());
        }
        let scheme = if tls { "https" } else { "http" };
        if listen_ip.is_loopback() {
            for host in ["127.0.0.1", "localhost", "[::1]"] {
                let _: bool =
                    origins.insert(format!("{scheme}://{host}:{}", self.server.listen_port));
            }
        } else {
            match (tls, listen_ip) {
                (true, IpAddr::V4(address)) => {
                    let _: bool =
                        origins.insert(format!("{scheme}://{address}:{}", self.server.listen_port));
                }
                (true, IpAddr::V6(address)) => {
                    let _: bool = origins.insert(format!(
                        "{scheme}://[{address}]:{}",
                        self.server.listen_port
                    ));
                }
                (false, IpAddr::V4(_) | IpAddr::V6(_)) => {}
            }
        }
        if origins.is_empty() {
            return Err(invalid(
                "web.public_url",
                "Web UI origin allowlist must not be empty",
            ));
        }
        Ok(origins.into_iter().collect())
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
        if !is_valid_router_id(&self.name) {
            return Err(invalid(
                "routers.name",
                "must be 1-32 characters of [a-z0-9-]",
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
        match (&self.read_login, &self.read_password_file) {
            (None, None) => {}
            (Some(login), Some(_)) if !login.is_empty() => {}
            (Some(_) | None, Some(_)) | (Some(_), None) => {
                return Err(invalid(
                    field("read_login"),
                    "set both non-empty read_login and read_password_file, or neither",
                ));
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

/// Whether `id` is a valid router identifier.
/// Rule: 1-32 bytes, lowercase letters, digits and `-`.
pub(crate) fn is_valid_router_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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

/// Validates DNS suffixes and rewrites them to lowercase leading-dot form.
///
/// # Errors
/// Returns [`ConfigError::Invalid`] when a suffix is empty or not a valid DNS name.
fn normalize_suffixes(suffixes: &mut Vec<String>) -> Result<(), ConfigError> {
    for suffix in suffixes {
        let name = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        let valid = !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        if !valid {
            return Err(invalid(
                "outbound.allowed_suffixes",
                "must contain valid DNS suffixes such as keenetic.pro",
            ));
        }
        *suffix = format!(".{name}");
    }
    Ok(())
}
