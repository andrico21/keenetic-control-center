//! Safety net: running-configuration snapshot, fail-safe timer, end-of-suite comparison.

use core::{error::Error, fmt};

use kcc_config::config_text::normalize;
use kcc_rci::{ConfigKind, RciClient};
use secrecy::ExposeSecret as _;
use zeroize::Zeroizing;

/// Arms the router fail-safe timer: an unconfirmed change reboots into startup after 900 s.
pub(crate) const ARM: &str = "system configuration fail-safe timer reboot 900";

/// Disarms the fail-safe timer, keeping the (identical) running configuration unsaved.
pub(crate) const DISARM: &str = "no system configuration fail-safe timer";

/// The running configuration after the suite differs from the snapshot taken before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SnapshotMismatch {
    /// Lines present on only one side; values are never reported.
    pub differing_lines: usize,
}

impl fmt::Display for SnapshotMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "running-config differs from the suite-start snapshot in {} lines; the fail-safe \
             timer stays armed and rolls the router back",
            self.differing_lines
        )
    }
}

impl Error for SnapshotMismatch {}

/// Reads and normalizes `/ci/running-config.txt`.
///
/// # Errors
/// Returns transport, UTF-8 or parse failures.
// cancel-safe: one read.
pub(crate) async fn snapshot(client: &RciClient) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let bytes = client.download_config(ConfigKind::Running).await?;
    let text = Zeroizing::new(String::from_utf8(bytes.expose_secret().to_vec())?);
    Ok(Zeroizing::new(normalize(&text)?))
}

/// Compares the current normalized running configuration with `before`.
///
/// # Errors
/// Returns [`SnapshotMismatch`] or read failures.
// cancel-safe: one read.
pub(crate) async fn compare(client: &RciClient, before: &str) -> Result<(), Box<dyn Error>> {
    let after = snapshot(client).await?;
    if after.as_str() == before {
        return Ok(());
    }
    let only_before = before
        .lines()
        .filter(|line| !after.lines().any(|other| other == *line));
    let only_after = after
        .lines()
        .filter(|line| !before.lines().any(|other| other == *line));
    Err(SnapshotMismatch {
        differing_lines: only_before
            .count()
            .saturating_add(only_after.count())
            .max(1),
    }
    .into())
}
