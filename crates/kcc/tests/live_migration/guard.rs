//! Write gate of the live migration rehearsal: test-device profile, then serial allowlist.

use core::{error::Error, fmt};
use std::path::Path;

use kcc_app::settings::{Config, OutboundConfig, RouterProfile};
use kcc_rci::RouterUrl;
use kcc_testkit::capture::{CaptureError, Connection, connect, verify_serial};
use secrecy::SecretString;

/// Why the rehearsal refuses a target before any write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The kcc configuration has no `[[routers]]` entry for the target URL.
    ProfileMissing,
    /// The target profile lacks `test_device = true`.
    NotTestDevice,
    /// The serial from `show identification` is not in `KCC_LIVE_ALLOW_SERIAL`.
    SerialNotAllowed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProfileMissing => "target URL has no router profile",
            Self::NotTestDevice => "target profile is not marked test_device = true",
            Self::SerialNotAllowed => "target serial is not in KCC_LIVE_ALLOW_SERIAL",
        })
    }
}

impl Error for Refusal {}

/// Inputs to the write gate.
pub(crate) struct Gate<'gate> {
    /// kcc configuration naming the target profile.
    pub config: &'gate Path,
    /// Target origin.
    pub url: &'gate str,
    /// Target account.
    pub login: &'gate str,
    /// Target password.
    pub password: SecretString,
    /// Allowed serials.
    pub allowed: &'gate [String],
    /// Permits loopback targets (hermetic tests only).
    pub allow_loopback: bool,
}

/// An admitted target: a test device whose serial is allowlisted.
pub(crate) struct Admitted {
    /// The matching configuration profile.
    pub profile: RouterProfile,
    /// Outbound policy of the same configuration.
    pub outbound: OutboundConfig,
    /// Authenticated connection used only for reads before admission.
    pub connection: Connection,
}

/// Checks the profile before contacting the router, then the serial with one read.
///
/// # Errors
/// Returns a [`Refusal`], or configuration and transport failures; never writes.
// cancel-safe: reads configuration and one router show only.
pub(crate) async fn admit(gate: Gate<'_>) -> Result<Admitted, Box<dyn Error>> {
    let config = Config::load(gate.config)?;
    let wanted = normalized(gate.url);
    let outbound = config.outbound;
    let profile = config
        .routers
        .into_iter()
        .find(|profile| normalized(profile.url.as_str()) == wanted)
        .ok_or(Refusal::ProfileMissing)?;
    if !profile.test_device {
        return Err(Refusal::NotTestDevice.into());
    }
    let router = gate.url.parse::<RouterUrl>()?;
    let connection = connect(
        router,
        gate.login.to_owned(),
        gate.password,
        gate.allow_loopback,
    )
    .await?;
    match verify_serial(&connection.client, gate.allowed).await {
        Ok(_serial) => Ok(Admitted {
            profile,
            outbound,
            connection,
        }),
        Err(CaptureError::SerialNotAllowed) => Err(Refusal::SerialNotAllowed.into()),
        Err(error) => Err(error.into()),
    }
}

/// Compares origins without a trailing slash.
fn normalized(url: &str) -> &str {
    url.trim_end_matches('/')
}
