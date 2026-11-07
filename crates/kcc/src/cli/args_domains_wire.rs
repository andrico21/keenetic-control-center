//! Domain commands: KeenDNS, log, DNS, VPN, interfaces, internet connections, Wi-Fi and
//! mesh.

use clap::Subcommand;

use super::args_domains::Toggle;

/// KeenDNS commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum KeenDnsCommand {
    /// Booked names and cloud state.
    Status,
    /// Book a name.
    Book {
        /// Name.
        name: String,
        /// KeenDNS domain.
        domain: String,
    },
    /// Release a name.
    Drop {
        /// Name.
        name: String,
        /// KeenDNS domain.
        domain: String,
    },
    /// Enable or disable a web proxy entry.
    Proxy {
        /// Proxy name.
        name: String,
        /// On or off.
        state: Toggle,
    },
}

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

/// DNS commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DnsCommand {
    /// DNS proxy state.
    Proxy,
    /// Configured resolvers, records and lists.
    Config,
}

/// VPN client commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum VpnCommand {
    /// List VPN connections.
    List,
}

/// VPN server commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum VpnServerCommand {
    /// VPN server configuration and state.
    Status,
}

/// Interface commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum InterfacesCommand {
    /// List interfaces.
    List,
    /// Show one interface.
    Show {
        /// Interface name.
        name: String,
    },
    /// Traffic counters.
    Stats,
    /// Bring an interface up.
    Up {
        /// Interface name.
        name: String,
    },
    /// Take an interface down (a management change when it carries kcc's traffic).
    Down {
        /// Interface name.
        name: String,
    },
    /// Set the description.
    Description {
        /// Interface name.
        name: String,
        /// Description.
        text: String,
    },
}

/// Internet connection commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum WanCommand {
    /// List connections.
    List,
    /// Set the PPP login.
    Identity {
        /// Connection name.
        name: String,
        /// Login.
        identity: String,
    },
    /// Set the PPP password (from `--password-file`, `KCC_PASSWORD` or a prompt).
    Password {
        /// Connection name.
        name: String,
    },
    /// Set the priority.
    Priority {
        /// Connection name.
        name: String,
        /// Priority.
        value: i64,
    },
    /// Set the MTU.
    Mtu {
        /// Connection name.
        name: String,
        /// MTU.
        value: i64,
    },
    /// Use the connection as a default route.
    DefaultRoute {
        /// Connection name.
        name: String,
        /// On or off.
        state: Toggle,
    },
}

/// Wi-Fi commands; an access point is named by `--ap`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum WifiCommand {
    /// Radios.
    Radios,
    /// One access point.
    Ap {
        /// Access point name, e.g. `WifiMaster0/AccessPoint0`.
        #[arg(long)]
        ap: String,
    },
    /// Associated stations.
    Stations,
    /// Set the network name.
    SetSsid {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Network name.
        ssid: String,
    },
    /// Set the WPA key (from `--password-file`, `KCC_PASSWORD` or a hidden prompt).
    SetPsk {
        /// Access point name.
        #[arg(long)]
        ap: String,
    },
    /// Hide or show the network name.
    Hide {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Hidden (`on`) or broadcast (`off`).
        state: Toggle,
    },
    /// Turn an access point on or off.
    Enable {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// On or off.
        state: Toggle,
    },
    /// Set the channel.
    Channel {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Channel or `auto`.
        channel: String,
    },
    /// Set the transmit power.
    Power {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Percent.
        power: i64,
    },
    /// Set the country code.
    Country {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Two-letter code.
        code: String,
    },
}

/// Mesh commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum MeshCommand {
    /// Mesh members.
    Members,
    /// Station associations.
    Associations,
    /// Ask a member to check for updates.
    UpdateCheck {
        /// Member id.
        member: String,
    },
    /// Start a member update.
    UpdateStart {
        /// Member id.
        member: String,
    },
}
