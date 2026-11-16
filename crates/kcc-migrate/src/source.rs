//! Read-only migration source loading.

use core::{fmt, fmt::Write as _, str, str::FromStr as _};

use kcc_config::config_text::{Ast, ConfigHeader, ParseError, parse};
use kcc_rci::{RciError, capabilities::RouterInfo, version::FirmwareVersion};
use md5::{Digest as _, Md5};
use thiserror::Error;

/// One item that must be supplied by an operator before migration can continue safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NeededInput {
    /// Source router model is absent or unknown.
    Model,
    /// Source firmware version is absent or malformed.
    FirmwareVersion,
}

impl fmt::Display for NeededInput {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model => f.write_str("needs-input: model"),
            Self::FirmwareVersion => f.write_str("needs-input: firmware-version"),
        }
    }
}

/// Parsed migration source and any identity detected without mutating a router.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the plan names the parsed aggregate SourceConfig"
)]
pub struct SourceConfig {
    /// Parsed configuration header.
    pub header: ConfigHeader,
    /// Parsed startup configuration.
    pub ast: Ast,
    /// Live-router identity, or header-derived identity when enough data is known.
    pub info: Option<RouterInfo>,
    /// Catalog hardware id derived from the header model name.
    pub hw_id: Option<String>,
    /// Parsed source firmware version.
    pub firmware: Option<FirmwareVersion>,
    /// Operator inputs still required.
    pub needs_input: Vec<NeededInput>,
}

impl SourceConfig {
    /// Parses uploaded configuration bytes and validates an advertised MD5 checksum.
    ///
    /// # Errors
    ///
    /// Returns an error for non-UTF-8 input, malformed configuration text, or a checksum mismatch.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SourceError> {
        let text = str::from_utf8(bytes).map_err(|_error| SourceError::InvalidUtf8)?;
        let ast = parse(text)?;
        verify_checksum(text, &ast.header)?;
        let header = ast.header.clone();
        let hw_id = header
            .model
            .as_deref()
            .and_then(model_hw_id)
            .map(str::to_owned);
        let firmware = header
            .version
            .as_deref()
            .and_then(|value| FirmwareVersion::from_str(value).ok());
        let mut needs_input = Vec::new();
        if hw_id.is_none() {
            needs_input.push(NeededInput::Model);
        }
        if firmware.is_none() {
            needs_input.push(NeededInput::FirmwareVersion);
        }
        Ok(Self {
            header,
            ast,
            info: None,
            hw_id,
            firmware,
            needs_input,
        })
    }

    /// Returns the source firmware after applying an explicit operator override.
    #[inline]
    #[must_use]
    pub const fn firmware_or(&self, explicit: Option<FirmwareVersion>) -> Option<FirmwareVersion> {
        match self.firmware {
            Some(version) => Some(version),
            None => explicit,
        }
    }
}

/// Source loading failures.
#[derive(Debug, Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public error type identifies its source domain"
)]
pub enum SourceError {
    /// Uploaded bytes are not UTF-8 configuration text.
    #[error("source configuration is not UTF-8")]
    InvalidUtf8,
    /// Configuration syntax is malformed.
    #[error("source configuration could not be parsed")]
    Parse(#[from] ParseError),
    /// Header checksum differs from the configuration body.
    #[error("source configuration checksum does not match")]
    ChecksumMismatch,
    /// Live authentication failed; upload a configuration file instead.
    #[error("live source authentication failed; use an uploaded configuration file")]
    UseUploadedFile,
    /// Other read-only RCI failure.
    #[error("live source could not be read")]
    Rci(#[from] RciError),
    /// Backup ids require the caller's backup store.
    #[error("backup source must be resolved by the backup store")]
    BackupNotResolved,
}

/// Checks the header checksum against the exact post-header configuration body.
///
/// # Errors
///
/// Returns [`SourceError::ChecksumMismatch`] when the advertised digest differs.
fn verify_checksum(text: &str, header: &ConfigHeader) -> Result<(), SourceError> {
    let Some(expected) = header.md5.as_deref() else {
        return Ok(());
    };
    let joined_body = text
        .lines()
        .skip_while(|line| line.trim_start().starts_with("! $$$ "))
        .collect::<Vec<_>>()
        .join("\n");
    let body = if text.ends_with('\n') && !joined_body.is_empty() {
        format!("{joined_body}\n")
    } else {
        joined_body
    };
    let mut actual = String::with_capacity(32);
    for byte in Md5::digest(body.as_bytes()) {
        let _result = write!(actual, "{byte:02x}");
    }
    if actual.eq_ignore_ascii_case(expected.trim()) {
        Ok(())
    } else {
        Err(SourceError::ChecksumMismatch)
    }
}

/// Maps catalog-backed marketing model names to hardware ids.
fn model_hw_id(model: &str) -> Option<&'static str> {
    const MODELS: &[(&str, &str)] = &[
        ("Keenetic Giga", "KN-1010"),
        ("Keenetic Ultra", "KN-1811"),
        ("Keenetic Hopper", "KN-3810"),
        ("Netcraze Speedster", "NC-3013"),
    ];
    MODELS
        .iter()
        .find(|(name, _id)| name.eq_ignore_ascii_case(model.trim()))
        .map(|(_name, id)| *id)
        .or_else(|| {
            let normalized = model.trim().to_ascii_uppercase();
            (normalized.starts_with("KN-") || normalized.starts_with("NC-"))
                .then(|| {
                    MODELS
                        .iter()
                        .find(|(_name, id)| *id == normalized)
                        .map(|pair| pair.1)
                })
                .flatten()
        })
}
