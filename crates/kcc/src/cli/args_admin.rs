//! Account, API key, audit and TLS commands.

use std::path::PathBuf;

use clap::Subcommand;

/// Web UI account commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum UserCommand {
    /// Add an account (password from `--password-file`, `KCC_PASSWORD` or a prompt).
    Add {
        /// Login name.
        username: String,
        /// Role name.
        #[arg(long, default_value = "viewer")]
        role: String,
        /// Preferred language.
        #[arg(long, default_value = "en")]
        locale: String,
    },
    /// Change an account password; the new one comes from `--password-file`.
    Passwd {
        /// Login name.
        username: String,
        /// File holding the current password (else a prompt).
        #[arg(long, value_name = "PATH")]
        current_password_file: Option<PathBuf>,
    },
    /// List accounts.
    List,
    /// Disable an account, or enable it again with `--enable`.
    Disable {
        /// Login name.
        username: String,
        /// Enable instead of disabling.
        #[arg(long)]
        enable: bool,
    },
}

/// MCP API key commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ApiKeyCommand {
    /// Create a key and print it once.
    Create {
        /// Key name, also the MCP principal.
        name: String,
        /// Role name.
        #[arg(long, default_value = "viewer")]
        role: String,
    },
    /// List keys without their secrets.
    List,
    /// Revoke a key.
    Revoke {
        /// Key name.
        name: String,
    },
}

/// First-run commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum AdminCommand {
    /// Create the first administrator and print its generated password once.
    Init {
        /// Login name.
        #[arg(long, default_value = "admin")]
        username: String,
    },
}

/// Audit log commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum AuditCommand {
    /// Check the hash chain; exit 1 naming the first broken sequence.
    Verify,
}

/// TLS commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum TlsCommand {
    /// Write a self-signed certificate and key into the config directory.
    SelfSigned {
        /// Host name the certificate is for; repeat for several.
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        /// Directory to write `kcc-cert.pem` and `kcc-key.pem` into.
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
}
