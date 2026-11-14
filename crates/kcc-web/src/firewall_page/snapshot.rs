//! The router's firewall as the page reads it: through the firewall domain, with a read
//! that failed told as the page tells it.

use kcc_domain::{
    DomainError, RouterCtx,
    firewall::{lists::Firewall, read},
};
use kcc_i18n::{bundle::MessageKey, keys};

/// The router's firewall, from its running configuration.
///
/// # Errors
///
/// Returns why the configuration could not be read.
// cancel-safe: reads only.
pub(crate) async fn read(domain: &RouterCtx) -> Result<Firewall, MessageKey> {
    read::firewall(domain)
        .await
        .map_err(|failure| match failure {
            DomainError::Rci(error) => {
                tracing::warn!(?error, "firewall page: running configuration unavailable");
                keys::WEB_KIT_UNREACHABLE
            }
            DomainError::InvalidResponse | _ => keys::WEB_KIT_FAILED,
        })
}
