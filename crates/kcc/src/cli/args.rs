//! The command line: global options and the top-level command tree.
//!
//! Exit codes: 0 ok, 1 generic error, 2 usage, 3 authentication, 4 validation (nothing
//! sent), 5 conflict or busy, 6 router error, 7 partial batch, 10 refused by policy.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

use super::{
    args_admin::{
        AdminCommand, ApiKeyCommand, AuditCommand, NotifyCommand, TlsCommand, UserCommand,
    },
    args_dom_jobs::ConfigCommand,
    args_domains::DomainCommand,
    args_fleet::{BackupCommand, CatalogCommand, RciCommand, RouterCommand},
    args_migrate::MigrateCommand,
    preset::args::{CopyCommand, PresetCommand},
};

/// Keenetic Control Center: manage Keenetic and Netcraze routers.
#[derive(Debug, Parser)]
#[command(name = "kcc", version, about, propagate_version = true)]
#[non_exhaustive]
pub struct Cli {
    /// Path to `kcc.toml` (default: `kcc.toml` in the platform config directory).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Router profile id to act on (default: the only configured router).
    #[arg(long, global = true, value_name = "ID")]
    pub router: Option<String>,
    /// Print one JSON document instead of localized text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Language of human output: en, ru, uk, de, be or kk.
    #[arg(long, global = true, value_name = "CODE")]
    pub lang: Option<String>,
    /// Answer "yes" to ordinary confirmations (never to destructive ones).
    #[arg(long, global = true)]
    pub yes: bool,
    /// Confirm a destructive operation by naming its router id.
    #[arg(long, global = true, value_name = "ROUTER-ID")]
    pub confirm_destructive: Option<String>,
    /// Read the secret this command needs from a file (else `KCC_PASSWORD`, else a prompt).
    #[arg(long, global = true, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every top-level command.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// Commands on the router profiles, the state directory and the server's files.
    #[command(flatten)]
    Local(LocalCommand),
    /// Run the HTTP MCP server and optional Web UI.
    Serve,
    /// Run an MCP transport.
    #[command(subcommand)]
    Mcp(McpCommand),
    /// Print a shell completion script.
    Completions {
        /// Target shell.
        shell: Shell,
    },
    /// Curated router domains.
    #[command(flatten)]
    Domain(DomainCommand),
}

/// The commands on the router profiles, the state directory and the server's files.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum LocalCommand {
    /// Router profiles.
    #[command(subcommand)]
    Router(RouterCommand),
    /// Model, firmware and support tier of the router.
    Info,
    /// Run a validated `show` command, e.g. `kcc show interface`.
    Show {
        /// Words of the show command after `show`.
        #[arg(required = true, num_args = 1..)]
        words: Vec<String>,
    },
    /// Catalog-validated raw RCI requests.
    #[command(subcommand)]
    Rci(RciCommand),
    /// Search and describe the router's command catalog.
    #[command(subcommand)]
    Catalog(CatalogCommand),
    /// Saving, fail-safe timer and change state.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Encrypted startup-configuration backups.
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Configuration migration onto the router.
    #[command(subcommand)]
    Migrate(MigrateCommand),
    /// Settings presets captured from one router and applied to another.
    #[command(subcommand)]
    Preset(PresetCommand),
    /// Copy settings groups from a router, backup or file onto another router.
    Copy(CopyCommand),
    /// Web UI accounts.
    #[command(subcommand)]
    User(UserCommand),
    /// MCP API keys.
    #[command(subcommand)]
    Apikey(ApiKeyCommand),
    /// First-run administration.
    #[command(subcommand)]
    Admin(AdminCommand),
    /// The tamper-evident audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Check the local server's `/healthz` once (exit 0 on HTTP 200).
    Healthcheck,
    /// TLS certificates for the server.
    #[command(subcommand)]
    Tls(TlsCommand),
    /// Telegram notifications: settings, bot token, chats and a test message.
    #[command(subcommand)]
    Notify(NotifyCommand),
}

/// MCP transport commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum McpCommand {
    /// Run MCP over the local process's stdin and stdout.
    Stdio,
}

impl Cli {
    /// Parses the process arguments, returning clap's error for help, version or misuse.
    ///
    /// # Errors
    ///
    /// Returns clap's error, whose exit code is 0 for help and version and 2 otherwise.
    #[inline]
    pub fn try_parse_process() -> Result<Self, clap::Error> {
        Self::try_parse()
    }
}
