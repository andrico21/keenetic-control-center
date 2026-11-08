//! Read-only migration source loading.

use core::{fmt, fmt::Write as _, str, str::FromStr as _};

use kcc_config::config_text::{Ast, ConfigHeader, ParseError, parse};
use kcc_rci::{
    ConfigKind, OutboundPolicy, RciClient, RciClientOptions, RciError, RouterUrl,
    auth::Credentials, capabilities::RouterInfo, version::FirmwareVersion,
};
use md5::{Digest as _, Md5};
use thiserror::Error;

/// A configured live router used only as a migration source.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LiveRouterProfile {
    /// Validated router origin.
    pub router: RouterUrl,
    /// Credentials supporting ndw2 or ndw4 authentication.
    pub credentials: Credentials,
}

/// A source from which a startup configuration can be obtained.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the plan names the public enum MigrationSource"
)]
pub enum MigrationSource {
    /// A live router. Loading performs reads only.
    LiveRouter(LiveRouterProfile),
    /// Uploaded configuration bytes.
    File(Vec<u8>),
    /// Identifier resolved by the caller's backup store.
    Backup(String),
}

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

    /// Loads a live source through authenticated read-only endpoints.
    ///
    /// Only `show version` and `/ci/startup-config.txt` are queried. Any firmware line is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::UseUploadedFile`] when authentication fails, otherwise a typed read,
    /// parsing, or checksum error.
    // cancel-safe: every router operation is a read.
    #[inline]
    pub async fn from_live(profile: &LiveRouterProfile) -> Result<Self, SourceError> {
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let client =
            RciClient::connect_with(profile.router.clone(), profile.credentials.clone(), options)
                .await?;
        let info = client.detect().await.map_err(auth_fallback)?;
        let bytes = client
            .download_config(ConfigKind::Startup)
            .await
            .map_err(auth_fallback)?;
        let mut source = Self::from_bytes(secrecy::ExposeSecret::expose_secret(&bytes))?;
        source.firmware = info.firmware.or(source.firmware);
        source.hw_id = info.hw_id().map(str::to_owned).or(source.hw_id);
        source.needs_input.retain(|item| match item {
            NeededInput::Model => source.hw_id.is_none(),
            NeededInput::FirmwareVersion => source.firmware.is_none(),
        });
        source.info = Some(info);
        Ok(source)
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

/// Loads a source, using `backup` only for backup identifiers.
///
/// # Errors
///
/// Returns source parsing/read errors or [`SourceError::BackupNotResolved`] when the callback does
/// not recognize an id.
// cancel-safe: live-source operations are reads; file and backup parsing is synchronous.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "the plan's source-loading operation is named load_source"
)]
pub async fn load_source<F>(source: MigrationSource, backup: F) -> Result<SourceConfig, SourceError>
where
    F: FnOnce(&str) -> Option<Vec<u8>>,
{
    match source {
        MigrationSource::LiveRouter(profile) => SourceConfig::from_live(&profile).await,
        MigrationSource::File(bytes) => SourceConfig::from_bytes(&bytes),
        MigrationSource::Backup(id) => backup(&id)
            .ok_or(SourceError::BackupNotResolved)
            .and_then(|bytes| SourceConfig::from_bytes(&bytes)),
    }
}

/// Maps an authentication failure to the actionable uploaded-file fallback.
fn auth_fallback(error: RciError) -> SourceError {
    match error {
        RciError::Auth(_auth) => SourceError::UseUploadedFile,
        other @ (RciError::Transport
        | RciError::Timeout
        | RciError::Http { status: _ }
        | RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message: _,
        }
        | RciError::NotFound
        | RciError::MethodNotAllowed
        | RciError::BodyTooLarge
        | RciError::Decode
        | RciError::Policy
        | RciError::Validation
        | _) => SourceError::Rci(other),
    }
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
