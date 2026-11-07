//! Gate of the live domain campaign: write profile first, then the serial allowlist.

use core::{error::Error, fmt};
use std::path::Path;

use kcc_app::settings::{Config, OutboundConfig, RouterProfile};
use kcc_rci::RouterUrl;
use kcc_testkit::capture::{CaptureError, Connection, connect, verify_serial};

use super::campaign::{Options, WriteMode};

/// Why the campaign refuses a router.
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

/// The write admission: the test-device profile and the outbound policy beside it.
pub(crate) struct WriteAdmission {
    /// Matching `test_device = true` profile.
    pub profile: RouterProfile,
    /// Outbound policy of the same configuration.
    pub outbound: OutboundConfig,
}

/// An opened router whose serial is allowlisted.
pub(crate) struct Opened {
    /// Authenticated connection.
    pub connection: Connection,
    /// The allowlisted serial (hashed before it is recorded anywhere).
    pub serial: String,
    /// Write admission; `None` in read-only mode.
    pub write: Option<WriteAdmission>,
}

/// Checks the write profile without contacting the router, then reads the serial.
///
/// # Errors
/// Returns a [`Refusal`], or configuration and transport failures; never writes.
// cancel-safe: reads configuration and one router show only.
pub(crate) async fn open(options: &Options) -> Result<Opened, Box<dyn Error>> {
    let write = match &options.write {
        WriteMode::ReadOnly => None,
        WriteMode::Requested(config) => Some(admission(config, &options.url)?),
    };
    let router = options.url.parse::<RouterUrl>()?;
    let connection = connect(
        router,
        options.login.clone(),
        options.password.clone(),
        options.allow_loopback,
    )
    .await?;
    let serial = match verify_serial(&connection.client, &options.allowed).await {
        Ok(serial) => serial,
        Err(CaptureError::SerialNotAllowed) => return Err(Refusal::SerialNotAllowed.into()),
        Err(error) => return Err(error.into()),
    };
    Ok(Opened {
        connection,
        serial,
        write,
    })
}

/// Finds the `test_device = true` profile for `url` in the kcc configuration.
///
/// # Errors
/// Returns a [`Refusal`] or the configuration load failure.
fn admission(path: &Path, url: &str) -> Result<WriteAdmission, Box<dyn Error>> {
    let config = Config::load(path)?;
    let wanted = url.trim_end_matches('/');
    let outbound = config.outbound;
    let profile = config
        .routers
        .into_iter()
        .find(|profile| profile.url.as_str().trim_end_matches('/') == wanted)
        .ok_or(Refusal::ProfileMissing)?;
    if !profile.test_device {
        return Err(Refusal::NotTestDevice.into());
    }
    Ok(WriteAdmission { profile, outbound })
}
