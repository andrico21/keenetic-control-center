//! Curated domain commands: one subcommand per domain, and the system and internet commands.

use clap::{Subcommand, ValueEnum};

use super::{
    args_dom_admin::{FirewallCommand, KeenDnsCommand, SchedulesCommand, ServicesCommand},
    args_dom_dns::DnsCommand,
    args_dom_entware::EntwareCommand,
    args_dom_jobs::{ComponentsCommand, DiagnosticsCommand},
    args_dom_lan::{ClientsCommand, DhcpCommand, PoliciesCommand, SegmentsCommand},
    args_dom_link::{InterfacesCommand, MeshCommand, WanCommand, WifiCommand},
    args_dom_vpn::VpnCommand,
    args_dom_vpn_server::VpnServerCommand,
    args_domains_net::{NatCommand, RouterUsersCommand, RoutesCommand, StorageCommand},
    args_domains_wire::LogCommand,
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
    /// Router diagnostics.
    #[command(subcommand)]
    Diagnostics(DiagnosticsCommand),
    /// Connected and registered clients.
    #[command(subcommand)]
    Clients(ClientsCommand),
    /// DHCP pools, leases, bindings and neighbours.
    #[command(subcommand)]
    Dhcp(DhcpCommand),
    /// Network segments.
    #[command(subcommand)]
    Segments(SegmentsCommand),
    /// Router login accounts.
    #[command(subcommand, name = "router-users")]
    RouterUsers(RouterUsersCommand),
    /// Static routes and routing tables.
    #[command(subcommand)]
    Routes(RoutesCommand),
    /// Connection policies.
    #[command(subcommand)]
    Policies(PoliciesCommand),
    /// NAT and port forwarding.
    #[command(subcommand)]
    Nat(NatCommand),
    /// Access lists and UPnP.
    #[command(subcommand)]
    Firewall(FirewallCommand),
    /// Router services.
    #[command(subcommand)]
    Services(ServicesCommand),
    /// Firmware components.
    #[command(subcommand)]
    Components(ComponentsCommand),
    /// Attached storage.
    #[command(subcommand)]
    Storage(StorageCommand),
    /// Schedules.
    #[command(subcommand)]
    Schedules(SchedulesCommand),
    /// KeenDNS and remote access.
    #[command(subcommand)]
    Keendns(KeenDnsCommand),
    /// Router log reading and configuration.
    #[command(subcommand)]
    Log(LogCommand),
    /// DNS proxy.
    #[command(subcommand)]
    Dns(DnsCommand),
    /// VPN client connections.
    #[command(subcommand)]
    Vpn(VpnCommand),
    /// VPN servers.
    #[command(subcommand, name = "vpn-server")]
    VpnServer(VpnServerCommand),
    /// Interfaces.
    #[command(subcommand)]
    Interfaces(InterfacesCommand),
    /// Internet connections.
    #[command(subcommand)]
    Wan(WanCommand),
    /// Wi-Fi access points, radios and stations.
    #[command(subcommand)]
    Wifi(WifiCommand),
    /// Mesh members.
    #[command(subcommand)]
    Mesh(MeshCommand),
    /// Entware: the `opkg` package system on a drive.
    #[command(subcommand)]
    Entware(EntwareCommand),
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
