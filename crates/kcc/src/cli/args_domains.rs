//! Curated domain commands: system, internet, diagnostics, clients, DHCP and segments.

use core::net::Ipv4Addr;

use clap::{Subcommand, ValueEnum};

use super::{
    args_dom_admin::{
        FirewallWriteCommand, KeenDnsWriteCommand, SchedulesWriteCommand, ServicesWriteCommand,
        StorageWriteCommand,
    },
    args_dom_dns::DnsWriteCommand,
    args_dom_family::Family,
    args_dom_jobs::{ComponentsWriteCommand, DiagnosticsWriteCommand},
    args_dom_lan::{
        ClientsWriteCommand, DhcpWriteCommand, PoliciesWriteCommand, SegmentsWriteCommand,
    },
    args_dom_link::{InterfacesWriteCommand, MeshWriteCommand, WanWriteCommand, WifiWriteCommand},
    args_dom_vpn::{VpnSecretCommand, VpnWriteCommand},
    args_dom_vpn_server::{VpnServerSecretCommand, VpnServerWriteCommand},
    args_domains_net::{
        ComponentsCommand, FirewallCommand, NatCommand, PoliciesCommand, RouterUsersCommand,
        RoutesCommand, SchedulesCommand, ServicesCommand, StorageCommand,
    },
    args_domains_wire::{
        DnsCommand, InterfacesCommand, KeenDnsCommand, LogCommand, MeshCommand, VpnCommand,
        VpnServerCommand, WanCommand, WifiCommand,
    },
};

/// One subcommand per curated domain of `kcc-domain`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DomainCommand {
    /// Router identity, clock and global settings.
    #[command(subcommand)]
    System(SystemCommand),
    /// Internet state and ping-check profiles.
    #[command(subcommand)]
    Internet(InternetCommand),
    /// Router log and diagnostics.
    #[command(subcommand)]
    Diagnostics(Family<DiagnosticsCommand, DiagnosticsWriteCommand>),
    /// Connected and registered clients.
    #[command(subcommand)]
    Clients(Family<ClientsCommand, ClientsWriteCommand>),
    /// DHCP pools, leases, bindings and neighbours.
    #[command(subcommand)]
    Dhcp(Family<DhcpCommand, DhcpWriteCommand>),
    /// Network segments.
    #[command(subcommand)]
    Segments(Family<SegmentsCommand, SegmentsWriteCommand>),
    /// Router login accounts.
    #[command(subcommand, name = "router-users")]
    RouterUsers(RouterUsersCommand),
    /// Static routes and routing tables.
    #[command(subcommand)]
    Routes(RoutesCommand),
    /// Connection policies.
    #[command(subcommand)]
    Policies(Family<PoliciesCommand, PoliciesWriteCommand>),
    /// NAT and port forwarding.
    #[command(subcommand)]
    Nat(NatCommand),
    /// Access lists and UPnP.
    #[command(subcommand)]
    Firewall(Family<FirewallCommand, FirewallWriteCommand>),
    /// Router services.
    #[command(subcommand)]
    Services(Family<ServicesCommand, ServicesWriteCommand>),
    /// Firmware components.
    #[command(subcommand)]
    Components(Family<ComponentsCommand, ComponentsWriteCommand>),
    /// Attached storage.
    #[command(subcommand)]
    Storage(Family<StorageCommand, StorageWriteCommand>),
    /// Schedules.
    #[command(subcommand)]
    Schedules(Family<SchedulesCommand, SchedulesWriteCommand>),
    /// KeenDNS and remote access.
    #[command(subcommand)]
    Keendns(Family<KeenDnsCommand, KeenDnsWriteCommand>),
    /// Router log reading and configuration.
    #[command(subcommand)]
    Log(LogCommand),
    /// DNS proxy.
    #[command(subcommand)]
    Dns(Family<DnsCommand, DnsWriteCommand>),
    /// VPN client connections.
    #[command(subcommand)]
    Vpn(Family<VpnCommand, Family<VpnWriteCommand, VpnSecretCommand>>),
    /// VPN servers.
    #[command(subcommand, name = "vpn-server")]
    VpnServer(Family<VpnServerCommand, Family<VpnServerWriteCommand, VpnServerSecretCommand>>),
    /// Interfaces.
    #[command(subcommand)]
    Interfaces(Family<InterfacesCommand, InterfacesWriteCommand>),
    /// Internet connections.
    #[command(subcommand)]
    Wan(Family<WanCommand, WanWriteCommand>),
    /// Wi-Fi access points, radios and stations.
    #[command(subcommand)]
    Wifi(Family<WifiCommand, WifiWriteCommand>),
    /// Mesh members.
    #[command(subcommand)]
    Mesh(Family<MeshCommand, MeshWriteCommand>),
}

/// An on or off switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Toggle {
    /// Enable.
    On,
    /// Disable.
    Off,
}

impl Toggle {
    /// Whether this is `on`.
    #[inline]
    #[must_use]
    pub const fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

/// System commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SystemCommand {
    /// Firmware version.
    Version,
    /// CPU, memory and uptime.
    State,
    /// Clock and time zone.
    Clock,
    /// NTP status.
    Ntp,
    /// Operating mode.
    Mode,
    /// Set the host name.
    SetHostname {
        /// New value.
        value: String,
    },
    /// Set the domain name.
    SetDomain {
        /// New value.
        value: String,
    },
    /// Set the description.
    SetDescription {
        /// New value.
        value: String,
    },
    /// Set the time zone locality, e.g. `Europe/Berlin`.
    SetTimezone {
        /// New value.
        value: String,
    },
    /// Set the NTP server.
    SetNtpServer {
        /// New value.
        value: String,
    },
    /// Serve time to the LAN.
    NtpMaster {
        /// On or off.
        state: Toggle,
    },
    /// Set the NTP sync period.
    NtpSyncPeriod {
        /// Seconds.
        seconds: u32,
    },
    /// Reboot the router (destructive).
    Reboot,
    /// Reset the router to factory defaults (destructive).
    FactoryReset,
}

/// Internet commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum InternetCommand {
    /// Internet availability.
    Status,
    /// Ping-check profiles.
    PingCheck,
}

/// Diagnostics commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DiagnosticsCommand {
    /// The last lines of the router log.
    Log {
        /// Most lines to read.
        #[arg(long, default_value_t = 100)]
        lines: u32,
    },
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
}

/// Segment commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SegmentsCommand {
    /// List segments.
    List,
}
