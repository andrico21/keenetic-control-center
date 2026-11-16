//! HTTP delivery to configured log destinations.

use core::{fmt, time::Duration};
use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};
use kcc_app::{
    secrets::files::{SecretFileError, read_secret_file_async},
    settings::LogSinkConfig,
};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;
use tokio::fs;

use super::{format, loki_reply, types::LogRecord};

/// A configured Loki push client.
pub struct LokiClient {
    /// No-redirect HTTP client with normal certificate verification.
    client: Client,
    /// Fully resolved Loki push endpoint from operator configuration.
    endpoint: String,
    /// Optional Loki tenant header value.
    tenant: Option<String>,
    /// Redacted authentication material loaded from configured files.
    auth: Auth,
    /// Whether request bodies are gzip encoded.
    compress: bool,
}

impl fmt::Debug for LokiClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LokiClient")
            .field("endpoint", &self.endpoint)
            .field("tenant", &self.tenant)
            .field("auth", &self.auth)
            .field("compress", &self.compress)
            .finish_non_exhaustive()
    }
}

impl LokiClient {
    /// Loads credentials and CA material from a Loki sink configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for a non-Loki configuration, unreadable secret or CA file,
    /// invalid CA certificate, or HTTP client construction failure.
    // cancel-safe: file reads do not mutate application state.
    #[inline]
    pub async fn load(config: &LogSinkConfig) -> Result<Self, DeliveryError> {
        let LogSinkConfig::Loki {
            url,
            tenant,
            basic_auth_user,
            password_file,
            bearer_token_file,
            ca_file,
            compress,
        } = config
        else {
            return Err(DeliveryError::WrongKind);
        };
        let auth = Auth::load(
            basic_auth_user.as_deref(),
            password_file.as_deref(),
            bearer_token_file.as_deref(),
        )
        .await?;
        let mut builder = Client::builder().no_proxy().redirect(Policy::none());
        if let Some(path) = ca_file {
            let pem = fs::read(path)
                .await
                .map_err(|_error| DeliveryError::ReadFile)?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|_error| DeliveryError::Certificate)?;
            builder = builder.add_root_certificate(certificate);
        }
        drop(default_provider().install_default());
        Ok(Self {
            client: builder.build().map_err(|_error| DeliveryError::Client)?,
            endpoint: format!("{}/loki/api/v1/push", url.as_str().trim_end_matches('/')),
            tenant: tenant.clone(),
            auth,
            compress: *compress,
        })
    }

    /// Delivers one bounded batch to Loki.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when serialization, compression, transport, or the remote
    /// HTTP status indicates failure.
    // NOT cancel-safe: cancellation after the request reaches Loki can lead to a retry of
    // an already accepted batch; Loki's timestamp and line identity make that retry safe.
    #[inline]
    pub async fn send(&self, records: &[LogRecord]) -> Result<(), DeliveryError> {
        let payload = format::loki(records).map_err(|_error| DeliveryError::Payload)?;
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(tenant) = &self.tenant {
            request = request.header("x-scope-orgid", tenant);
        }
        request = self.auth.apply(request);
        let body = if self.compress {
            request = request.header(header::CONTENT_ENCODING, "gzip");
            gzip(&payload)?
        } else {
            payload
        };
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|_error| DeliveryError::Transport)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let delay = retry_after(response.headers());
        if status == StatusCode::BAD_REQUEST {
            let reply = loki_reply::read_body(response).await;
            if let Some(rejected) = loki_reply::rejected_entries(&reply, records.len()) {
                return Err(DeliveryError::PartiallyAccepted { rejected });
            }
        }
        Err(DeliveryError::Status {
            status,
            retry_after: delay,
        })
    }
}

/// Authentication material, always redacted by `Debug`.
pub(super) enum Auth {
    /// No authentication header.
    None,
    /// HTTP Basic credentials.
    Basic {
        /// HTTP Basic username.
        user: String,
        /// HTTP Basic password.
        password: SecretString,
    },
    /// Bearer token credentials.
    Bearer(SecretString),
    /// Elasticsearch/OpenSearch API key credentials.
    ApiKey(SecretString),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Basic { user, password: _ } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Bearer(_) => f.write_str("Bearer([REDACTED])"),
            Self::ApiKey(_) => f.write_str("ApiKey([REDACTED])"),
        }
    }
}

impl Auth {
    /// Loads the one validated authentication mode.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for unreadable secret files or an invalid combination.
    // cancel-safe: file reads do not mutate application state.
    async fn load(
        configured_user: Option<&str>,
        password_file: Option<&Path>,
        bearer_file: Option<&Path>,
    ) -> Result<Self, DeliveryError> {
        match (configured_user, password_file, bearer_file) {
            (Some(user), Some(path), None) => Ok(Self::Basic {
                user: user.to_owned(),
                password: read_secret(path).await?,
            }),
            (None, None, Some(path)) => Ok(Self::Bearer(read_secret(path).await?)),
            (None, None, None) => Ok(Self::None),
            _ => Err(DeliveryError::InvalidAuth),
        }
    }

    /// Loads an Elasticsearch/OpenSearch API key or Basic credentials.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for unreadable secret files or an invalid combination.
    // cancel-safe: file reads do not mutate application state.
    pub(super) async fn load_search(
        configured_user: Option<&str>,
        password_file: Option<&Path>,
        api_key_file: Option<&Path>,
    ) -> Result<Self, DeliveryError> {
        match (configured_user, password_file, api_key_file) {
            (Some(user), Some(path), None) => Ok(Self::Basic {
                user: user.to_owned(),
                password: read_secret(path).await?,
            }),
            (None, None, Some(path)) => Ok(Self::ApiKey(read_secret(path).await?)),
            (None, None, None) => Ok(Self::None),
            _ => Err(DeliveryError::InvalidAuth),
        }
    }

    /// Applies authentication without exposing a secret to formatting or errors.
    pub(super) fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::None => request,
            Self::Basic { user, password } => {
                request.basic_auth(user, Some(password.expose_secret()))
            }
            Self::Bearer(token) => request.bearer_auth(token.expose_secret()),
            Self::ApiKey(key) => request.header(
                header::AUTHORIZATION,
                format!("ApiKey {}", key.expose_secret()),
            ),
        }
    }
}

/// Sink construction or delivery failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeliveryError {
    /// The supplied configuration is for another sink kind.
    #[error("log sink configuration is not Loki")]
    WrongKind,
    /// Authentication fields violate the validated configuration contract.
    #[error("log sink authentication configuration is invalid")]
    InvalidAuth,
    /// A configured secret or CA file cannot be read.
    #[error("cannot read a configured log sink file")]
    ReadFile,
    /// Group or others can read a configured secret file (unix only).
    #[error("log sink secret file {path} can be read by other users (chmod 600)")]
    SecretPermissions {
        /// Secret file path.
        path: PathBuf,
    },
    /// A configured CA file is not a PEM certificate.
    #[error("configured log sink CA is not a valid PEM certificate")]
    Certificate,
    /// The HTTP client could not be constructed.
    #[error("cannot construct log sink HTTP client")]
    Client,
    /// Payload serialization failed.
    #[error("cannot serialize log sink payload")]
    Payload,
    /// Gzip encoding failed.
    #[error("cannot compress log sink payload")]
    Compress,
    /// The request could not be sent or answered.
    #[error("log sink transport failed")]
    Transport,
    /// The destination rejected the request.
    #[error("log sink returned HTTP {status}")]
    Status {
        /// HTTP response status.
        status: StatusCode,
        /// Server-requested retry delay, when present as delta seconds.
        retry_after: Option<Duration>,
    },
    /// Loki stored part of the push and refused `rejected` entries for good.
    #[error("log sink refused {rejected} entries of the push")]
    PartiallyAccepted {
        /// Number of refused entries.
        rejected: usize,
    },
}

impl DeliveryError {
    /// Returns whether retry policy may resubmit the request.
    #[inline]
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::Status {
                status,
                retry_after: _,
            } => status.as_u16() == 429 || status.is_server_error(),
            Self::WrongKind
            | Self::InvalidAuth
            | Self::ReadFile
            | Self::SecretPermissions { path: _ }
            | Self::Certificate
            | Self::Client
            | Self::Payload
            | Self::Compress
            | Self::Transport
            | Self::PartiallyAccepted { rejected: _ } => false,
        }
    }

    /// Returns the server-requested retry delay.
    #[inline]
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Status {
                status: _,
                retry_after,
            } => *retry_after,
            Self::WrongKind
            | Self::InvalidAuth
            | Self::ReadFile
            | Self::SecretPermissions { path: _ }
            | Self::Certificate
            | Self::Client
            | Self::Payload
            | Self::Compress
            | Self::Transport
            | Self::PartiallyAccepted { rejected: _ } => None,
        }
    }
}

/// Parses an HTTP `Retry-After` delta-seconds value.
pub(super) fn retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Reads a line-oriented secret without retaining its newline.
///
/// # Errors
///
/// Returns [`DeliveryError::ReadFile`] when the configured file cannot be read, or
/// [`DeliveryError::SecretPermissions`] when group or others can read it.
// cancel-safe: the read does not mutate application state.
pub(super) async fn read_secret(path: &Path) -> Result<SecretString, DeliveryError> {
    read_secret_file_async(path)
        .await
        .map_err(|error| match error {
            SecretFileError::Permissions { path: refused } => {
                DeliveryError::SecretPermissions { path: refused }
            }
            SecretFileError::Read { path: _, source: _ } | _ => DeliveryError::ReadFile,
        })
}

/// Compresses one already-bounded request body.
///
/// # Errors
///
/// Returns [`DeliveryError::Compress`] when gzip encoding fails.
pub(super) fn gzip(payload: &[u8]) -> Result<Vec<u8>, DeliveryError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .map_err(|_error| DeliveryError::Compress)?;
    encoder.finish().map_err(|_error| DeliveryError::Compress)
}
