//! The live safety contract every live suite goes through before it reads or writes a router.
//!
//! First the router's profile in `KCC_LIVE_TARGET_CONFIG` must carry `test_device = true`,
//! checked without contacting the router; then every router the suite contacts must report
//! a serial listed in `KCC_LIVE_ALLOW_SERIAL` through `show identification`.

use core::{error::Error, fmt};
use std::path::Path;

use kcc_app::settings::{Config, OutboundConfig, RouterProfile};
use kcc_rci::RciClient;
use kcc_testkit::capture::{CaptureError, verify_serial};

/// Why a live suite refuses a router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The kcc configuration has no `[[routers]]` entry for the router URL.
    ProfileMissing,
    /// The router profile lacks `test_device = true`.
    NotTestDevice,
    /// The serial from `show identification` is not in `KCC_LIVE_ALLOW_SERIAL`.
    SerialNotAllowed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProfileMissing => "router URL has no router profile",
            Self::NotTestDevice => "router profile is not marked test_device = true",
            Self::SerialNotAllowed => "router serial is not in KCC_LIVE_ALLOW_SERIAL",
        })
    }
}

impl Error for Refusal {}

/// The admitted test-device profile and the outbound policy of the same configuration.
pub(crate) struct Admission {
    /// Matching `test_device = true` profile.
    pub profile: RouterProfile,
    /// Outbound policy every client kcc builds for the suite must follow.
    pub outbound: OutboundConfig,
}

/// Finds the `test_device = true` profile for `url` in the kcc configuration at `config`;
/// the router is not contacted.
///
/// # Errors
/// Returns a [`Refusal`] or the configuration load failure.
pub(crate) fn admission(config: &Path, url: &str) -> Result<Admission, Box<dyn Error>> {
    let loaded = Config::load(config)?;
    let wanted = url.trim_end_matches('/');
    let profile = loaded
        .routers
        .into_iter()
        .find(|profile| profile.url.as_str().trim_end_matches('/') == wanted)
        .ok_or(Refusal::ProfileMissing)?;
    if !profile.test_device {
        return Err(Refusal::NotTestDevice.into());
    }
    let admitted = Admission {
        profile,
        outbound: loaded.outbound,
    };
    tracing::info!(
        profile = admitted.profile.name,
        networks = admitted.outbound.allowed_networks.len(),
        "test-device profile admitted"
    );
    Ok(admitted)
}

/// Reads the serial with `show identification` and requires it in `allowed`.
///
/// # Errors
/// Returns [`Refusal::SerialNotAllowed`] or the read failure; sends nothing else.
// cancel-safe: one read.
pub(crate) async fn allowlisted(
    client: &RciClient,
    allowed: &[String],
) -> Result<String, Box<dyn Error>> {
    match verify_serial(client, allowed).await {
        Ok(serial) => Ok(serial),
        Err(CaptureError::SerialNotAllowed) => Err(Refusal::SerialNotAllowed.into()),
        Err(error) => Err(error.into()),
    }
}
