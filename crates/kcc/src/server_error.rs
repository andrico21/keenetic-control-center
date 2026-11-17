//! The failures and outcomes of `kcc serve` and `kcc mcp stdio`.

use std::{io, path::PathBuf};

use kcc_app::{
    composition::CoreError, jobs::JobError, permissions::PermissionError, persist::StateError,
    registry::RegistryError, secrets::files::SecretFileError, settings::ConfigError,
};
use kcc_telemetry::{logs::runtime::StartError, metrics::failure::MetricsError};
use kcc_web::admin::ReloadError;
use rmcp_server_kit::RmcpServerKitError;

use crate::server_tls_key::readable;

/// Why a server process could not start or stopped with an error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// No `--config` was given and the platform has no configuration directory.
    #[error("no config path and no platform config directory")]
    NoConfigPath,
    /// The configuration could not be read, overridden or validated.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// The MCP server kit failed: tracing, metrics, its configuration or its transport.
    #[error("{0}")]
    Kit(#[from] RmcpServerKitError),
    /// The state directory could not be opened or read.
    #[error("{0}")]
    State(#[from] StateError),
    /// Another `kcc serve` holds the state directory's server lock.
    #[error(
        "cannot start kcc serve with state directory {}: another kcc serve holds the server lock ({source})",
        dir.display()
    )]
    ServerLock {
        /// The state directory.
        dir: PathBuf,
        /// The lock failure.
        #[source]
        source: StateError,
    },
    /// The TLS private key is readable by group or others.
    #[error("{}", readable(path))]
    TlsKeyReadable {
        /// The key file.
        path: PathBuf,
    },
    /// The TLS private key could not be read.
    #[error("{0}")]
    TlsKey(#[from] SecretFileError),
    /// The shared services (key, credentials, profiles, audit) could not be opened.
    #[error("{0}")]
    Core(#[from] CoreError),
    /// The router profiles could not be listed, connected or reloaded.
    #[error("{0}")]
    Registry(#[from] RegistryError),
    /// The roles could not be loaded.
    #[error("{0}")]
    Roles(#[from] PermissionError),
    /// The background job runner could not open its state.
    #[error("{0}")]
    Jobs(#[from] JobError),
    /// A reload could not be installed into the running transport.
    #[error("{0}")]
    Reload(#[from] ReloadError),
    /// Router log collection could not start.
    #[error("{0}")]
    Logs(#[from] StartError),
    /// Log collection is on but the self-metrics it reports to are unavailable.
    #[error("log metrics are unavailable")]
    LogMetricsUnavailable,
    /// The self-metrics or the metrics exporter could not be built.
    #[error("{0}")]
    Metrics(#[from] MetricsError),
    /// `mcp.stdio_role` names no role.
    #[error("configured stdio role {0:?} does not exist")]
    UnknownStdioRole(String),
    /// `web.default_locale` is not a supported locale.
    #[error("web.default_locale is unsupported")]
    UnsupportedLocale,
    /// The listener could not bind its address.
    #[error("bind {address}:{port}: {source}")]
    Bind {
        /// The configured listen address.
        address: String,
        /// The configured listen port.
        port: u16,
        /// The bind failure.
        #[source]
        source: io::Error,
    },
    /// The audit writer terminated, so the server drained and stopped.
    #[error("audit writer terminated")]
    AuditWriterTerminated,
}

/// Process outcome mapped to the exit-code contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Command completed successfully.
    Ok,
    /// Generic startup or runtime failure.
    Failed,
    /// A configured policy forbids the requested command.
    Forbidden,
}

impl Outcome {
    /// Stable process exit code.
    #[inline]
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Forbidden => 10,
        }
    }
}
