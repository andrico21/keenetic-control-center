//! Router, raw RCI, catalog and backup commands, and the fail-safe timer actions.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use super::args_router::{AddArgs, EditArgs};

/// Router profile commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RouterCommand {
    /// List the router profiles in scope.
    List,
    /// Add a router profile; its credentials are sealed (password from `--password-file`,
    /// `KCC_PASSWORD` or a prompt).
    Add(AddArgs),
    /// Change a router profile; options not given keep their value. A new URL, login or
    /// TLS pin needs `--new-password` or `--new-token`.
    Edit(EditArgs),
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
    /// Show the commands that differ between two backups, in order, with secrets redacted.
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
