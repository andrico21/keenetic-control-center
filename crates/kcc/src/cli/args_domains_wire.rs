//! Router log commands.

use clap::Subcommand;

use super::args_domains::Toggle;

/// Router log commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum LogCommand {
    /// The last lines of the router log.
    Read {
        /// Most lines to read.
        #[arg(long, default_value_t = 100)]
        lines: u32,
    },
    /// Send the log to a syslog server.
    Server {
        /// Server address.
        address: String,
        /// Server port.
        #[arg(long)]
        port: Option<u16>,
        /// On or off.
        state: Toggle,
    },
    /// Reduce repeated messages.
    Reduction {
        /// On or off.
        state: Toggle,
    },
    /// Suppress messages of one source.
    Suppress {
        /// Message source.
        ident: String,
        /// On or off.
        state: Toggle,
    },
    /// Clear the router log (destructive).
    Clear,
}
