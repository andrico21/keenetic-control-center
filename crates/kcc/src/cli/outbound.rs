//! Explaining the router outbound policy when it refuses a router address.
//!
//! kcc contacts only routers inside `[outbound] allowed_networks` (or
//! `allowed_suffixes`), and both are empty by default. A refusal names that setting and
//! the router's address, so a fresh install says what to change.

use core::{net::IpAddr, str::FromStr as _};

use kcc_app::registry::{RegistryError, RouterRegistry};
use kcc_i18n::keys;
use kcc_rci::{RciError, RouterUrl, TlsMode, outbound::is_metadata_address, session::HttpTimeouts};
use url::Url;

use super::exit::{Exit, Failure, Outcome};

/// Refuses `url` before anything is stored when the outbound policy does not admit it.
///
/// Resolves the host but sends nothing.
///
/// # Errors
///
/// Returns the explained policy refusal, or a validation failure for an invalid address.
// cancel-safe: resolution changes no state.
pub(crate) async fn check(registry: &RouterRegistry, url: &Url) -> Outcome {
    let target = RouterUrl::from_str(url.as_str())
        .map_err(|error| Failure::text(Exit::Validation, &error))?;
    registry
        .outbound_policy()
        .client_builder(&target, &TlsMode::Verify, HttpTimeouts::default())
        .await
        .map(drop)
        .map_err(|_policy| refused(url))
}

/// The failure of `error` for the router at `url`; an outbound-policy refusal is explained.
pub(crate) fn explained(error: RegistryError, url: &Url) -> Failure {
    if matches!(error, RegistryError::Rci(RciError::Policy)) {
        refused(url)
    } else {
        error.into()
    }
}

/// The localized refusal of the router at `url`.
fn refused(url: &Url) -> Failure {
    let host = url.host_str().unwrap_or_default();
    let metadata = host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(is_metadata_address);
    let key = if metadata {
        keys::ERRORS_OUTBOUND_METADATA
    } else {
        keys::ERRORS_OUTBOUND_REFUSED
    };
    Failure::message(Exit::Policy, key, &[("address", host)])
}
