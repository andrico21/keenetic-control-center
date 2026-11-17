//! Domain commands: router users, routes, NAT and storage, and the component queue actions.

use clap::{Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// Router account commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RouterUsersCommand {
    /// List router accounts.
    List,
    /// Add an account (management change).
    Add {
        /// Account name.
        name: String,
        /// Service tag, e.g. `cli` or `http`; repeat for several.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Grant or revoke one service tag.
    Tag {
        /// Account name.
        name: String,
        /// Service tag.
        tag: String,
        /// Grant (`on`) or revoke (`off`).
        state: Toggle,
    },
    /// Set an account password (from `--password-file`, `KCC_PASSWORD` or a prompt).
    Passwd {
        /// Account name.
        name: String,
    },
    /// Delete an account.
    Delete {
        /// Account name.
        name: String,
    },
}

/// One static route on the command line.
#[derive(Debug, Clone, clap::Args)]
#[non_exhaustive]
pub struct RouteArgs {
    /// Destination network, host, or `default`; an IPv6 prefix with `--ipv6`.
    #[arg(long)]
    pub destination: String,
    /// IPv4 network mask.
    #[arg(long)]
    pub mask: Option<String>,
    /// Next hop.
    #[arg(long)]
    pub gateway: Option<String>,
    /// Egress interface.
    #[arg(long)]
    pub interface: Option<String>,
    /// IPv4 metric.
    #[arg(long)]
    pub metric: Option<u32>,
    /// The route is IPv6.
    #[arg(long)]
    pub ipv6: bool,
}

/// Routing commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RoutesCommand {
    /// The routing table.
    List {
        /// Show the IPv6 table.
        #[arg(long)]
        ipv6: bool,
    },
    /// Add a static route.
    Add(RouteArgs),
    /// Remove one static route (guarded against router-wide clears).
    Remove(RouteArgs),
}

/// Forwarded protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ForwardProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// One port forward on the command line.
#[derive(Debug, Clone, clap::Args)]
#[non_exhaustive]
pub struct ForwardArgs {
    /// Protocol.
    #[arg(long, value_enum)]
    pub protocol: ForwardProtocol,
    /// Inbound interface, e.g. `ISP`.
    #[arg(long)]
    pub interface: String,
    /// Inbound port.
    #[arg(long)]
    pub port: u16,
    /// LAN address to forward to.
    #[arg(long)]
    pub to_address: String,
    /// LAN port, when it differs.
    #[arg(long)]
    pub to_port: Option<u16>,
}

/// NAT commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum NatCommand {
    /// Running port forwards.
    Forwards,
    /// Saved port forwards.
    StartupForwards,
    /// Interfaces with NAT.
    Interfaces,
    /// One page of NAT sessions.
    Sessions {
        /// First row.
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Add a port forward.
    AddForward(ForwardArgs),
    /// Remove a port forward.
    RemoveForward(ForwardArgs),
    /// Enable NAT on an interface.
    AddInterface {
        /// Interface name.
        name: String,
    },
    /// Disable NAT on an interface.
    RemoveInterface {
        /// Interface name.
        name: String,
    },
}

/// Component queue actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum QueueChoice {
    /// Stage installation.
    Install,
    /// Stage removal.
    Remove,
}

/// Storage commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum StorageCommand {
    /// Mounted volumes.
    Media,
    /// USB devices.
    Usb,
    /// Eject a volume (destructive).
    Eject {
        /// Volume name.
        media: String,
    },
}
