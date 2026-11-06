//! Minimal command tree for server transports.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Keenetic Control Center.
#[derive(Debug, Parser)]
#[command(version, about)]
#[non_exhaustive]
pub struct Cli {
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Commands available before the complete todo-47 CLI lands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// Run the HTTP MCP server and optional Web UI.
    Serve {
        /// Path to `kcc.toml`.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run an MCP transport.
    #[command(subcommand)]
    Mcp(McpCommand),
}

/// MCP transport commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpCommand {
    /// Run MCP over the local process's stdin and stdout.
    Stdio {
        /// Path to `kcc.toml`.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

impl Cli {
    /// Parses process arguments according to the command schema.
    #[inline]
    #[must_use]
    pub fn parse_process() -> Self {
        Self::parse()
    }
}
