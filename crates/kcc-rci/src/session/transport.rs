//! Transport setup and unauthenticated probes bound to an existing session.

use core::time::Duration;
use std::sync::OnceLock;

use reqwest::Response;
use rustls::crypto::{CryptoProvider, ring::default_provider};

use super::{Manager, map_reqwest_error};
use crate::{LocalCause, RciError, RouterUrl, TransportCause};

/// Probes only the origin for which the session transport was constructed.
///
/// # Errors
/// Returns policy errors for a different origin, or transport and timeout failures.
// cancel-safe: the GET installs no cookie or other local state.
pub(super) async fn probe_auth(
    manager: &Manager,
    router: &RouterUrl,
) -> Result<Response, RciError> {
    if router != &manager.router {
        return Err(RciError::Policy);
    }
    manager
        .client
        .get(manager.url("/auth"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| map_reqwest_error(&error))
}

/// Installs rustls ring once, accepting a provider installed by another crate.
///
/// # Errors
/// Returns a transport error when no provider can be installed or found.
pub(super) fn install_ring_provider() -> Result<(), RciError> {
    static INSTALL: OnceLock<Result<(), ()>> = OnceLock::new();
    INSTALL
        .get_or_init(|| {
            default_provider()
                .install_default()
                .map_err(|_provider| ())
                .or_else(|()| {
                    CryptoProvider::get_default()
                        .is_some()
                        .then_some(())
                        .ok_or(())
                })
        })
        .map_err(|()| RciError::Transport(TransportCause::Local(LocalCause::ClientBuild)))
}
