//! `kcc mcp`: the stdio transport, the effective MCP settings, and the connections and
//! clients of kcc's sign-in.

use clap::Subcommand;

/// MCP commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpCommand {
    /// Run MCP over the local process's stdin and stdout.
    Stdio,
    /// The effective MCP settings.
    #[command(subcommand)]
    Settings(McpSettingsCommand),
    /// Connections of MCP clients signed in with kcc accounts (grants).
    #[command(subcommand)]
    Connections(McpConnectionsCommand),
    /// MCP clients registered for kcc sign-in.
    #[command(subcommand)]
    Clients(McpClientsCommand),
}

/// `kcc mcp settings` commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpSettingsCommand {
    /// Show every Web-managed `[mcp]` value and where it comes from.
    Show,
}

/// `kcc mcp connections` commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpConnectionsCommand {
    /// List the live connections (no token or hash is shown).
    List,
    /// Revoke one connection; needs `--confirm-destructive <grant-id>`.
    Revoke {
        /// The connection's grant id (64 hex digits).
        grant_id: String,
    },
    /// Revoke every connection of an account; needs `--confirm-destructive <user>`.
    RevokeAccount {
        /// The account's login name.
        user: String,
    },
}

/// `kcc mcp clients` commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpClientsCommand {
    /// List the registered clients.
    List,
    /// Delete a client and revoke its connections; needs
    /// `--confirm-destructive <client-id>`.
    Delete {
        /// The client id (64 hex digits).
        id: String,
    },
}
