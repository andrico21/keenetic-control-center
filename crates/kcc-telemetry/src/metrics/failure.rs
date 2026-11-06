//! Exporter errors.

/// Exporter construction and registration failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    /// The prometheus registry refused a collector or a name.
    #[error("metrics registry error: {0}")]
    Prometheus(#[from] prometheus::Error),
    /// A family is missing from, or has the wrong type in, the catalogue.
    #[error("metric family {0} is not in the catalogue")]
    Catalogue(&'static str),
}
