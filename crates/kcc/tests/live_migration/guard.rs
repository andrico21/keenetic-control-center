//! Write gate of the live migration rehearsal: test-device profile, then serial allowlist.

use core::error::Error;
use std::path::Path;

use kcc_app::settings::{OutboundConfig, RouterProfile};
use kcc_rci::RouterUrl;
use kcc_testkit::capture::{Connection, connect};
use secrecy::SecretString;

use super::live_gate::{admission, allowlisted};

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
/// Returns a refusal, or configuration and transport failures; never writes.
// cancel-safe: reads configuration and one router show only.
pub(crate) async fn admit(gate: Gate<'_>) -> Result<Admitted, Box<dyn Error>> {
    let admitted = admission(gate.config, gate.url)?;
    let router = gate.url.parse::<RouterUrl>()?;
    let connection = connect(
        router,
        gate.login.to_owned(),
        gate.password,
        gate.allow_loopback,
    )
    .await?;
    drop(allowlisted(&connection.client, gate.allowed).await?);
    Ok(Admitted {
        profile: admitted.profile,
        outbound: admitted.outbound,
        connection,
    })
}
