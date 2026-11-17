//! HTTP client construction and bounded reply reading shared by the log sinks.

use core::time::Duration;
use std::path::Path;

use reqwest::{Client, Response, redirect::Policy};
use rustls::crypto::ring::default_provider;
use tokio::fs;

use super::sink::DeliveryError;

/// Longest wait for a sink's TCP and TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest time one sink request may take, from connecting to the end of the reply.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the HTTP client of one sink: no proxy, no redirects, normal certificate
/// verification plus the optional configured CA, and per-request timeouts.
///
/// # Errors
///
/// Returns [`DeliveryError`] for an unreadable or invalid CA file, or when the client cannot
/// be built.
// cancel-safe: reads one file and builds a value; nothing is shared until it returns.
pub(super) async fn client(ca_file: Option<&Path>) -> Result<Client, DeliveryError> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    if let Some(path) = ca_file {
        let pem = fs::read(path)
            .await
            .map_err(|_error| DeliveryError::ReadFile)?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).map_err(|_error| DeliveryError::Certificate)?;
        builder = builder.add_root_certificate(certificate);
    }
    drop(default_provider().install_default());
    builder.build().map_err(|_error| DeliveryError::Client)
}

/// Reads a whole reply body of at most `cap` bytes; `None` when the body is longer or
/// breaks off. Reading stops at the cap, so a longer body is never buffered whole.
// cancel-safe: reading a response body changes no state.
pub(super) async fn read_capped(mut response: Response, cap: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= cap => {
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(body),
            Ok(Some(_)) | Err(_) => return None,
        }
    }
}
