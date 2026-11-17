//! Elasticsearch and `OpenSearch` Bulk API delivery.

use core::{fmt, time::Duration};

use kcc_app::settings::{LogSinkConfig, SearchFlavor};
use reqwest::{Client, StatusCode, header};
use serde::Deserialize;
use thiserror::Error;

use super::{
    format,
    sink::{Auth, DeliveryError, retry_after},
    sink_http,
    types::LogRecord,
};

/// Longest Bulk API reply read; a longer reply counts as malformed.
const MAX_REPLY: usize = 8 * 1024 * 1024;

/// A configured Elasticsearch/OpenSearch Bulk API client.
pub struct ElasticsearchClient {
    /// No-redirect HTTP client with normal certificate verification and timeouts.
    client: Client,
    /// Fully resolved Bulk API endpoint from operator configuration.
    endpoint: String,
    /// Bulk API dialect.
    flavor: SearchFlavor,
    /// Optional target override.
    target: Option<String>,
    /// Redacted authentication material loaded from configured files.
    auth: Auth,
    /// Whether request bodies are gzip encoded.
    compress: bool,
}

impl fmt::Debug for ElasticsearchClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticsearchClient")
            .field("endpoint", &self.endpoint)
            .field("flavor", &self.flavor)
            .field("target", &self.target)
            .field("auth", &self.auth)
            .field("compress", &self.compress)
            .finish_non_exhaustive()
    }
}

impl ElasticsearchClient {
    /// Loads credentials and CA material from a search sink configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for the wrong sink kind, unreadable files, invalid CA
    /// certificates, invalid authentication, or HTTP client construction failure.
    // cancel-safe: file reads do not mutate application state.
    #[inline]
    pub async fn load(config: &LogSinkConfig) -> Result<Self, DeliveryError> {
        let LogSinkConfig::Elasticsearch {
            url,
            flavor,
            target,
            basic_auth_user,
            password_file,
            api_key_file,
            ca_file,
            compress,
        } = config
        else {
            return Err(DeliveryError::WrongKind);
        };
        let auth = Auth::load_search(
            basic_auth_user.as_deref(),
            password_file.as_deref(),
            api_key_file.as_deref(),
        )
        .await?;
        Ok(Self {
            client: sink_http::client(ca_file.as_deref()).await?,
            endpoint: format!("{}/_bulk", url.as_str().trim_end_matches('/')),
            flavor: *flavor,
            target: target.clone(),
            auth,
            compress: *compress,
        })
    }

    /// Delivers one bounded batch and classifies every Bulk API item.
    ///
    /// # Errors
    ///
    /// Returns [`BulkError`] for serialization, compression, transport, malformed or
    /// oversized responses, or whole-request HTTP failures. Transport, HTTP 429 and 5xx
    /// failures are retriable.
    // NOT cancel-safe: cancellation after dispatch can retry an accepted create operation;
    // duplicate create ids are represented as item-level drops by the destination.
    #[inline]
    pub async fn send(&self, records: &[LogRecord]) -> Result<BulkOutcome, BulkError> {
        let payload = format::bulk(records, self.flavor, self.target.as_deref())
            .map_err(|_error| DeliveryError::Payload)?;
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(header::CONTENT_TYPE, "application/x-ndjson");
        request = self.auth.apply(request);
        let body = if self.compress {
            request = request.header(header::CONTENT_ENCODING, "gzip");
            super::sink::gzip(&payload)?
        } else {
            payload
        };
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|_error| DeliveryError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(BulkError::Http {
                status,
                retriable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                retry_after: retry_after(response.headers()),
            });
        }
        let reply = sink_http::read_capped(response, MAX_REPLY)
            .await
            .ok_or(BulkError::Response)?;
        let payload_response =
            serde_json::from_slice::<BulkResponse>(&reply).map_err(|_error| BulkError::Response)?;
        classify(payload_response, records.len())
    }
}

/// Classification of one accepted Bulk API response.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BulkOutcome {
    /// Number of successfully created records.
    pub accepted: usize,
    /// Zero-based records that should be retried.
    pub retriable: Vec<usize>,
    /// Zero-based records permanently rejected by a 4xx response.
    pub dropped: Vec<usize>,
}

/// Bulk API delivery or response failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BulkError {
    /// Shared payload, client, file, compression, or transport failure.
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
    /// Whole-request HTTP failure.
    #[error("log sink returned HTTP {status}")]
    Http {
        /// HTTP response status.
        status: StatusCode,
        /// Whether pipeline policy may retry this request.
        retriable: bool,
        /// Server-requested retry delay, when present as delta seconds.
        retry_after: Option<Duration>,
    },
    /// Response JSON does not match the Bulk API schema.
    #[error("log sink returned a malformed Bulk API response")]
    Response,
    /// Response item count differs from the submitted record count.
    #[error("log sink returned an incomplete Bulk API response")]
    ItemCount,
}

impl BulkError {
    /// Returns whether retry policy may resubmit the whole request.
    #[inline]
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::Http {
                status: _,
                retriable,
                retry_after: _,
            } => *retriable,
            Self::Delivery(error) => error.is_retriable(),
            Self::Response | Self::ItemCount => false,
        }
    }

    /// Returns the server-requested retry delay.
    #[inline]
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Http {
                status: _,
                retriable: _,
                retry_after,
            } => *retry_after,
            Self::Delivery(error) => error.retry_after(),
            Self::Response | Self::ItemCount => None,
        }
    }
}

/// Top-level Bulk API response fields used for item classification.
#[derive(Deserialize)]
struct BulkResponse {
    /// One response object per submitted action.
    items: Vec<BulkItem>,
}

/// One Bulk API action result.
#[derive(Deserialize)]
struct BulkItem {
    /// Result of the submitted create action.
    create: BulkStatus,
}

/// Status fields retained from an action result.
#[derive(Deserialize)]
struct BulkStatus {
    /// Per-item HTTP-compatible status code.
    status: u16,
}

/// Classifies item statuses without retaining destination error text.
///
/// # Errors
///
/// Returns [`BulkError::ItemCount`] when the destination omits or adds item results.
fn classify(response: BulkResponse, expected: usize) -> Result<BulkOutcome, BulkError> {
    if response.items.len() != expected {
        return Err(BulkError::ItemCount);
    }
    let mut outcome = BulkOutcome {
        accepted: 0,
        retriable: Vec::new(),
        dropped: Vec::new(),
    };
    for (index, item) in response.items.into_iter().enumerate() {
        match item.create.status {
            200..=299 => outcome.accepted = outcome.accepted.saturating_add(1),
            429 | 500..=599 => outcome.retriable.push(index),
            400..=499 => outcome.dropped.push(index),
            _ => outcome.retriable.push(index),
        }
    }
    Ok(outcome)
}
