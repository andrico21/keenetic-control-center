//! Account, API key, audit and TLS commands.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

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
    /// Change an account password; another account is administratively reset.
    Passwd {
        /// Login name.
        username: String,
        /// File holding the current password for one's own account (else a prompt).
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

/// Telegram notification commands; the bot token is never an argument value.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum NotifyCommand {
    /// Show the settings, whether a bot token is set, and the chats.
    Show,
    /// Send notifications.
    Enable,
    /// Stop sending notifications.
    Disable,
    /// Store the bot token from `--file`, `--password-file`, `KCC_PASSWORD` or a hidden
    /// prompt, or remove it with `--clear`.
    Token {
        /// File holding the bot token, readable by its owner only.
        #[arg(long, value_name = "PATH", conflicts_with = "clear")]
        file: Option<PathBuf>,
        /// Remove the stored bot token.
        #[arg(long)]
        clear: bool,
    },
    /// The chats messages go to.
    #[command(subcommand)]
    Chat(NotifyChatCommand),
    /// Choose the events: a comma-separated list of event names, or `default`.
    Events {
        /// Event names such as `router_down_up,job_failed`, or `default`.
        events: String,
    },
    /// Choose the message language: en, ru, uk, de, be, kk, or `default`.
    Locale {
        /// Language tag, or `default` for the server's default language.
        tag: String,
    },
    /// Name clients by name and MAC address (`on`) or by a pseudonym (`off`).
    ClientDetails {
        /// `on` or `off`.
        switch: Switch,
    },
    /// Send one test message from this process.
    Test {
        /// Chat id to send to (default: the first listed chat).
        #[arg(long, value_name = "ID", allow_hyphen_values = true)]
        chat: Option<String>,
    },
}

/// Commands on the chats notifications go to.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum NotifyChatCommand {
    /// Add a chat.
    Add(NotifyChatArgs),
    /// Remove a chat.
    Remove {
        /// Chat id or `@username`.
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}

/// A chat to add.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct NotifyChatArgs {
    /// Chat id (such as -1001234567890) or public `@username`.
    #[arg(allow_hyphen_values = true)]
    pub id: String,
    /// How kcc names the chat: 1 to 64 characters.
    #[arg(long)]
    pub label: String,
    /// Forum topic to post in.
    #[arg(long, value_name = "ID")]
    pub thread: Option<i64>,
    /// Send without a notification sound.
    #[arg(long)]
    pub silent: bool,
}

/// An on or off setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Switch {
    /// On.
    On,
    /// Off.
    Off,
}
