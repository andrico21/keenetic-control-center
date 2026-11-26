//! Router credential options of `router add` and `router edit`. Every secret file is
//! input only: kcc reads it once, seals the contents and never references the file.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use kcc_app::settings::RouterAuth;

/// Sign-in scheme of a router profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum AuthMode {
    /// Pick from the router's challenge.
    Auto,
    /// `x-ndw2-interactive`.
    Ndw2,
    /// `x-ndw4-interactive`.
    Ndw4,
    /// Login token in `X-NDMA-TKN`.
    Token,
    /// HTTP digest (KeenDNS HTTP proxy).
    Digest,
}

impl From<AuthMode> for RouterAuth {
    #[inline]
    fn from(mode: AuthMode) -> Self {
        match mode {
            AuthMode::Auto => Self::Auto,
            AuthMode::Ndw2 => Self::Ndw2,
            AuthMode::Ndw4 => Self::Ndw4,
            AuthMode::Token => Self::Token,
            AuthMode::Digest => Self::Digest,
        }
    }
}

/// `router add`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct AddArgs {
    /// Profile id, `[a-z0-9-]{1,32}`.
    pub id: String,
    /// Router origin, e.g. `http://192.168.1.1`.
    #[arg(long)]
    pub url: String,
    /// Router login.
    #[arg(long, default_value = "admin")]
    pub login: String,
    /// Display name, any script, up to 64 characters; the id stays the key.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
    /// Free-form label; repeat for several.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Allow live tests against this router.
    #[arg(long)]
    pub test_device: bool,
    /// Accept exactly the TLS certificate with this SHA-256 (64 hex digits).
    #[arg(long, value_name = "HEX")]
    pub pin_sha256: Option<String>,
    /// Sign-in scheme, token and read-only login.
    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// `router edit`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct EditArgs {
    /// Profile id.
    pub id: String,
    /// New router origin.
    #[arg(long)]
    pub url: Option<String>,
    /// New router login.
    #[arg(long)]
    pub login: Option<String>,
    /// New display name, any script, up to 64 characters; the id stays the key.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
    /// Remove the display name.
    #[arg(long, conflicts_with = "label")]
    pub clear_label: bool,
    /// Replace the labels; repeat for several.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Allow (`true`) or forbid (`false`) live tests.
    #[arg(long, value_name = "BOOL")]
    pub test_device: Option<bool>,
    /// Pin the TLS certificate with this SHA-256.
    #[arg(long, value_name = "HEX")]
    pub pin_sha256: Option<String>,
    /// Store a new password (from `--password-file`, `KCC_PASSWORD` or a prompt).
    #[arg(long)]
    pub new_password: bool,
    /// Sign-in scheme, token and read-only login.
    #[command(flatten)]
    pub credentials: CredentialArgs,
    /// Credential replacements.
    #[command(flatten)]
    pub edits: CredentialEdits,
}

/// Credential options shared by `router add` and `router edit`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CredentialArgs {
    /// Sign-in scheme.
    #[arg(long, value_enum, value_name = "MODE")]
    pub auth: Option<AuthMode>,
    /// File holding the login token (only with `--auth token`; else `KCC_PASSWORD` or a
    /// prompt). Read once and sealed.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Login of the read-only polling account.
    #[arg(long, value_name = "NAME")]
    pub read_login: Option<String>,
    /// File holding the read-only password (else `KCC_PASSWORD` or a prompt). Read once
    /// and sealed.
    #[arg(long, value_name = "PATH")]
    pub read_password_file: Option<PathBuf>,
}

/// Credential replacement options of `router edit`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CredentialEdits {
    /// Store a new login token (from `--token-file`, `KCC_PASSWORD` or a prompt).
    #[arg(long)]
    pub new_token: bool,
    /// Store a new read-only password (from `--read-password-file`, `KCC_PASSWORD` or a
    /// prompt).
    #[arg(long)]
    pub new_read_password: bool,
    /// Remove the read-only polling login and its sealed password.
    #[arg(
        long,
        conflicts_with_all = ["read_login", "read_password_file", "new_read_password"]
    )]
    pub clear_read_login: bool,
}
