//! What every wizard's analysis shares: why a source or a target cannot be used, the
//! parsed source configuration, and a configuration line as the review shows it.

use kcc_config::config_text::{CliLine, Token};
use kcc_migrate::{inventory::InventoryError, source::SourceConfig};
use secrecy::{ExposeSecret as _, SecretString};

/// What `<redacted>` stands for in a shown line.
const REDACTED: &str = "<redacted>";

/// Why the analysis could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Problem {
    /// The source configuration cannot be read.
    Source,
    /// The source names no firmware, and none was typed in.
    FirmwareRequired,
    /// The target runs older firmware than the source.
    FirmwareOlder {
        /// The source's firmware.
        source: String,
        /// The target's firmware.
        target: String,
    },
    /// The target's firmware is below 4.3 or unknown.
    Unsupported,
    /// The target did not answer.
    Unreachable,
}

/// `line` with every encoded secret replaced, as the review shows it.
pub(crate) fn shown_line(mut line: CliLine) -> String {
    for token in &mut line.tokens {
        if let Token::Ns3(payload) = token {
            REDACTED.clone_into(payload);
        }
    }
    line.to_string()
}

/// The source configuration in `text`.
///
/// # Errors
///
/// Returns [`Problem::Source`] when it does not parse or its checksum does not match.
pub(crate) fn parse_source(text: &SecretString) -> Result<SourceConfig, Problem> {
    SourceConfig::from_bytes(text.expose_secret().as_bytes()).map_err(|_error| Problem::Source)
}

/// The problem an inventory failure means.
pub(crate) fn inventory_problem(error: &InventoryError) -> Problem {
    match error {
        InventoryError::SourceVersionRequired => Problem::FirmwareRequired,
        InventoryError::TargetFirmwareOlder {
            source_version,
            target_version,
        } => Problem::FirmwareOlder {
            source: source_version.to_string(),
            target: target_version.to_string(),
        },
        InventoryError::UnsupportedFirmware | InventoryError::Catalog => Problem::Unsupported,
        other @ (InventoryError::Rci(_)
        | InventoryError::ConfigEncoding
        | InventoryError::Parse(_)
        | _) => {
            tracing::warn!(error = %other, "migration target inventory failed");
            Problem::Unreachable
        }
    }
}
