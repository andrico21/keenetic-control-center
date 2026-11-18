//! Gate of the live domain campaign: the test-device profile first, then the serial allowlist.

use core::error::Error;

use kcc_rci::RouterUrl;
use kcc_testkit::capture::{Connection, connect};

use super::{
    campaign::Options,
    live_gate::{Admission, admission, allowlisted},
};

/// An opened router whose profile is a test device and whose serial is allowlisted.
pub(crate) struct Opened {
    /// Authenticated connection.
    pub connection: Connection,
    /// The allowlisted serial (hashed before it is recorded anywhere).
    pub serial: String,
    /// The admitted profile and its outbound policy, for the write workflow.
    pub admission: Admission,
}

/// Checks the profile without contacting the router, then reads the serial; read-only runs
/// pass the same gate as writes.
///
/// # Errors
/// Returns a refusal, or configuration and transport failures; never writes.
// cancel-safe: reads configuration and one router show only.
pub(crate) async fn open(options: &Options) -> Result<Opened, Box<dyn Error>> {
    let admission = admission(&options.config, &options.url)?;
    let router = options.url.parse::<RouterUrl>()?;
    let connection = connect(
        router,
        options.login.clone(),
        options.password.clone(),
        options.allow_loopback,
    )
    .await?;
    let serial = allowlisted(&connection.client, &options.allowed).await?;
    Ok(Opened {
        connection,
        serial,
        admission,
    })
}
