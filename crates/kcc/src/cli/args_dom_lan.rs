//! Write commands of the client, DHCP, segment and connection-policy domains.

use core::net::Ipv4Addr;

use clap::{Args, Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// A hotspot policy choice: permit, deny, or a named connection policy.
#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
#[non_exhaustive]
pub struct SelectionArgs {
    /// Permit network access.
    #[arg(long)]
    pub permit: bool,
    /// Deny network access.
    #[arg(long)]
    pub deny: bool,
    /// Apply this connection policy.
    #[arg(long, value_name = "POLICY")]
    pub policy: Option<String>,
}

/// More client commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ClientsWriteCommand {
    /// Set the hotspot policy of unregistered clients.
    DefaultPolicy(SelectionArgs),
    /// Set the hotspot policy of one interface.
    InterfacePolicy {
        /// Interface name, e.g. `Bridge0`.
        #[arg(long)]
        interface: String,
        /// The policy.
        #[command(flatten)]
        selection: SelectionArgs,
    },
}

/// More DHCP commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DhcpWriteCommand {
    /// Create or replace a DHCP pool; options not given take their defaults.
    Pool {
        /// Pool name, e.g. `_WEBADMIN`.
        name: String,
        /// First address handed out.
        #[arg(long)]
        begin: Ipv4Addr,
        /// Last address handed out.
        #[arg(long)]
        end: Ipv4Addr,
        /// Interface the pool serves, e.g. `Bridge0`.
        #[arg(long)]
        interface: Option<String>,
        /// Advertised default router (default: the first address).
        #[arg(long)]
        gateway: Option<Ipv4Addr>,
        /// Advertised DNS server; repeat for several.
        #[arg(long = "dns")]
        dns: Vec<Ipv4Addr>,
        /// Lease time in seconds.
        #[arg(long, default_value_t = 86_400)]
        lease_seconds: u64,
        /// Serve (`on`, the default) or stop serving (`off`) the pool.
        #[arg(long, value_enum, default_value = "on")]
        state: Toggle,
    },
}

/// More segment commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SegmentsWriteCommand {
    /// Create a segment: VLAN, bridge, address, DHCP pool and switch ports.
    Create {
        /// Segment number, used in the generated object names.
        id: u16,
        /// VLAN id.
        #[arg(long)]
        vlan: u16,
        /// Bridge address.
        #[arg(long)]
        address: Ipv4Addr,
        /// Bridge network mask.
        #[arg(long)]
        mask: Ipv4Addr,
        /// First DHCP address.
        #[arg(long)]
        dhcp_begin: Ipv4Addr,
        /// Last DHCP address.
        #[arg(long)]
        dhcp_end: Ipv4Addr,
        /// Switch port carrying the VLAN; repeat for several.
        #[arg(long = "port")]
        ports: Vec<String>,
        /// Access point to join to the segment.
        #[arg(long)]
        access_point: Option<String>,
        /// Connection policy to create for the segment.
        #[arg(long)]
        policy: Option<String>,
    },
    /// Delete a segment and the objects it created.
    Delete {
        /// Segment number.
        id: u16,
    },
}

/// Rate-limit directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum DirectionChoice {
    /// Traffic entering the interface.
    Input,
    /// Traffic leaving the interface.
    Output,
}

/// More connection-policy commands; `--remove` takes a setting away.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum PoliciesWriteCommand {
    /// Create a policy.
    Create {
        /// Policy name.
        name: String,
    },
    /// Delete a policy.
    Delete {
        /// Policy name.
        name: String,
    },
    /// Set the description, or clear it when `--text` is absent.
    Description {
        /// Policy name.
        name: String,
        /// Description.
        #[arg(long)]
        text: Option<String>,
    },
    /// Permit an interface in the policy.
    Permit {
        /// Policy name.
        name: String,
        /// Interface name.
        #[arg(long)]
        interface: String,
        /// Interface order.
        #[arg(long)]
        order: Option<u32>,
        /// Remove the interface instead.
        #[arg(long)]
        remove: bool,
    },
    /// Balance traffic over several interfaces.
    Multipath {
        /// Policy name.
        name: String,
        /// On or off.
        state: Toggle,
    },
    /// Add a route owned by the policy: a network with `--mask` and `--interface`, else
    /// a host through `--gateway`.
    Route {
        /// Policy name.
        name: String,
        /// Destination network or host.
        #[arg(long)]
        destination: String,
        /// Network mask.
        #[arg(long, requires = "interface")]
        mask: Option<String>,
        /// Egress interface of a network route.
        #[arg(long)]
        interface: Option<String>,
        /// Gateway of a host route.
        #[arg(long, conflicts_with = "mask", required_unless_present = "mask")]
        gateway: Option<String>,
        /// Route metric.
        #[arg(long)]
        metric: Option<u32>,
        /// Remove the route instead.
        #[arg(long)]
        remove: bool,
    },
    /// Limit an interface's rate; automatic when `--rate` is absent.
    RateLimit {
        /// Policy name.
        name: String,
        /// Interface name.
        #[arg(long)]
        interface: String,
        /// Traffic direction.
        #[arg(long, value_enum)]
        direction: DirectionChoice,
        /// Rate.
        #[arg(long)]
        rate: Option<u32>,
        /// Remove the limit instead.
        #[arg(long)]
        remove: bool,
    },
    /// Let the policy work on its own.
    Standalone {
        /// Policy name.
        name: String,
        /// On or off.
        state: Toggle,
    },
}
