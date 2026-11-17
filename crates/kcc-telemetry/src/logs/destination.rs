//! The loaded destination of one log sink worker.

use core::{fmt, slice};

use kcc_app::settings::{LogSinkConfig, SearchFlavor};

use super::{
    elastic_sink::ElasticsearchClient,
    format,
    sink::{DeliveryError, LokiClient},
    types::LogRecord,
};

/// Loaded destination adapter.
pub(super) enum Sink {
    /// Loki.
    Loki(LokiClient),
    /// Elasticsearch or `OpenSearch`.
    Search(ElasticsearchClient),
    /// Standard output.
    Stdout,
}
impl fmt::Debug for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loki(client) => f.debug_tuple("Loki").field(client).finish(),
            Self::Search(client) => f.debug_tuple("Search").field(client).finish(),
            Self::Stdout => f.write_str("Stdout"),
        }
    }
}

impl Sink {
    /// Loads one destination.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when setup fails.
    // cancel-safe: loading reads files and builds a client; nothing is shared until it returns.
    pub(super) async fn load(config: &LogSinkConfig) -> Result<Self, DeliveryError> {
        match config {
            LogSinkConfig::Loki {
                url: _,
                tenant: _,
                basic_auth_user: _,
                password_file: _,
                bearer_token_file: _,
                ca_file: _,
                compress: _,
            } => Ok(Self::Loki(LokiClient::load(config).await?)),
            LogSinkConfig::Elasticsearch {
                url: _,
                flavor: _,
                target: _,
                basic_auth_user: _,
                password_file: _,
                api_key_file: _,
                ca_file: _,
                compress: _,
            } => Ok(Self::Search(ElasticsearchClient::load(config).await?)),
            LogSinkConfig::Stdout => Ok(Self::Stdout),
            _ => Err(DeliveryError::WrongKind),
        }
    }
    /// The length of a request that carries `record` alone; `None` when encoding fails.
    pub(super) fn record_len(&self, record: &LogRecord) -> Option<usize> {
        let one = slice::from_ref(record);
        match self {
            Self::Loki(_) => format::loki(one),
            Self::Search(_) => format::bulk(one, SearchFlavor::Elasticsearch, None),
            Self::Stdout => format::stdout(one),
        }
        .ok()
        .map(|payload| payload.len())
    }
}
