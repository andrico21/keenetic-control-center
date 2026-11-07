//! Router, raw RCI, catalog, configuration and backup commands.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

/// Router profile commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RouterCommand {
    /// List the router profiles in scope.
    List,
    /// Add a router profile (password from `--password-file`, `KCC_PASSWORD` or a prompt).
    Add {
        /// Profile id, `[a-z0-9-]{1,32}`.
        id: String,
        /// Router origin, e.g. `http://192.168.1.1`.
        #[arg(long)]
        url: String,
        /// Router login.
        #[arg(long, default_value = "admin")]
        login: String,
        /// Free-form label; repeat for several.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Allow live tests against this router.
        #[arg(long)]
        test_device: bool,
        /// Accept exactly the TLS certificate with this SHA-256 (64 hex digits).
        #[arg(long, value_name = "HEX")]
        pin_sha256: Option<String>,
    },
    /// Change a router profile; options not given keep their value.
    Edit {
        /// Profile id.
        id: String,
        /// New router origin.
        #[arg(long)]
        url: Option<String>,
        /// New router login.
        #[arg(long)]
        login: Option<String>,
        /// Replace the labels; repeat for several.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Allow (`true`) or forbid (`false`) live tests.
        #[arg(long, value_name = "BOOL")]
        test_device: Option<bool>,
        /// Pin the TLS certificate with this SHA-256.
        #[arg(long, value_name = "HEX")]
        pin_sha256: Option<String>,
        /// Store a new password (from `--password-file`, `KCC_PASSWORD` or a prompt).
        #[arg(long)]
        new_password: bool,
    },
    /// Remove a router profile.
    Remove {
        /// Profile id.
        id: String,
    },
    /// Log in and detect the router without changing anything.
    Test,
}

/// Raw RCI requests; bodies come from `--data @file`, `--data -` (stdin) or inline JSON.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RciCommand {
    /// GET a catalog path, e.g. `kcc rci get show version`.
    Get {
        /// Words of the catalog path.
        #[arg(required = true, num_args = 1..)]
        path: Vec<String>,
        /// Query object.
        #[arg(long, value_name = "SOURCE")]
        data: Option<String>,
    },
    /// POST to a catalog path, or to the root endpoint when no path is given.
    Post {
        /// Words of the catalog path; empty for the root endpoint.
        path: Vec<String>,
        /// Request body.
        #[arg(long, value_name = "SOURCE")]
        data: String,
    },
    /// DELETE a catalog path.
    Delete {
        /// Words of the catalog path.
        #[arg(required = true, num_args = 1..)]
        path: Vec<String>,
        /// Query object.
        #[arg(long, value_name = "SOURCE")]
        data: Option<String>,
    },
    /// POST a JSON array of root objects as one batch.
    Batch {
        /// The array.
        #[arg(long, value_name = "SOURCE")]
        data: String,
    },
}

/// Catalog commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum CatalogCommand {
    /// Search command paths.
    Search {
        /// Search words.
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
        /// Most results to print.
        #[arg(long, default_value_t = 20)]
        limit: u16,
    },
    /// Print the JSON schema of one command.
    Describe {
        /// Words of the catalog path.
        #[arg(required = true, num_args = 1..)]
        path: Vec<String>,
    },
}

/// Configuration persistence commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ConfigCommand {
    /// Show unsaved changes, the last changing agent and the fail-safe timer.
    State,
    /// Save the running configuration.
    Save,
    /// Arm, commit or roll back the router's fail-safe timer.
    Failsafe {
        /// What to do.
        action: FailsafeAction,
        /// Timer length when arming, 300..=3600 seconds.
        #[arg(long, default_value_t = 900)]
        seconds: u64,
    },
}

/// Fail-safe timer actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum FailsafeAction {
    /// Arm the timer (destructive: the router reboots into its saved config).
    Arm,
    /// Keep the changes and stop the timer.
    Commit,
    /// Roll back to the saved configuration now (destructive).
    Rollback,
}

/// Backup commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum BackupCommand {
    /// Back up the router's startup configuration.
    Create {
        /// Reason word stored in the backup name.
        #[arg(long, default_value = "manual")]
        reason: String,
    },
    /// List the router's backups.
    List,
    /// Print a backup with secrets redacted, or write it in full to `--output`.
    Get {
        /// Backup name.
        name: String,
        /// Write the complete backup (secrets included) to this new file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Count the lines that differ between two backups.
    Diff {
        /// Older backup name.
        older: String,
        /// Newer backup name.
        newer: String,
    },
    /// Delete a backup (destructive).
    Delete {
        /// Backup name.
        name: String,
    },
}
