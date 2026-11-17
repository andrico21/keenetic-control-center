//! Client, DHCP, segment and connection-policy commands.

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

/// Client commands; a client is named by `--mac`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ClientsCommand {
    /// List clients.
    List,
    /// Show one client.
    Show {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
    },
    /// Register or rename a client.
    Register {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Name.
        #[arg(long)]
        name: String,
    },
    /// Forget a registered client.
    Remove {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
    },
    /// Permit or deny network access.
    Access {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Permit (`on`) or deny (`off`).
        state: Toggle,
    },
    /// Apply a schedule.
    Schedule {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Schedule name.
        schedule: String,
    },
    /// Apply a connection policy.
    Policy {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Policy name.
        policy: String,
    },
    /// Set the traffic priority.
    Priority {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Priority.
        priority: u8,
    },
    /// Send Wake-on-LAN.
    Wake {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
    },
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

/// DHCP commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DhcpCommand {
    /// DHCP pools.
    Pools,
    /// Static leases.
    Leases,
    /// Current bindings.
    Bindings,
    /// ARP neighbours.
    Neighbours,
    /// Add a static lease.
    StaticLease {
        /// Client MAC address.
        #[arg(long)]
        mac: String,
        /// Reserved address.
        #[arg(long)]
        address: Ipv4Addr,
    },
    /// Create or replace a DHCP pool. Replacing an existing pool needs `--lease-seconds`
    /// and `--state`, so they are not reset; an omitted `--interface` or `--dns` keeps
    /// the pool's own.
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
        /// Advertised default router, usually the interface's own address.
        #[arg(long)]
        gateway: Ipv4Addr,
        /// Advertised DNS server; a pool takes one.
        #[arg(long = "dns")]
        dns: Vec<Ipv4Addr>,
        /// Lease time in seconds (a new pool: 86400).
        #[arg(long)]
        lease_seconds: Option<u64>,
        /// Serve (`on`, a new pool's default) or stop serving (`off`) the pool.
        #[arg(long, value_enum)]
        state: Option<Toggle>,
    },
}

/// Segment commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SegmentsCommand {
    /// List segments.
    List,
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

/// Connection policy commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum PoliciesCommand {
    /// List policies.
    List,
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
