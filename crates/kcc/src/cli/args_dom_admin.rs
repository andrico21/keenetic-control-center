//! Firewall, service, schedule and KeenDNS commands.

use clap::{Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// Access-list verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum VerdictChoice {
    /// Accept matching traffic.
    Permit,
    /// Reject matching traffic.
    Deny,
}

/// Access-list protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum RuleProtocolChoice {
    /// Any IP protocol.
    Ip,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// ESP.
    Esp,
    /// GRE.
    Gre,
    /// IP in IP.
    Ipip,
}

/// Access-list binding directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum AclDirection {
    /// Traffic entering the interface.
    In,
    /// Traffic leaving the interface.
    Out,
}

/// Firewall commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum FirewallCommand {
    /// Access lists.
    AccessLists,
    /// UPnP redirects.
    Upnp,
    /// Add an access-list rule.
    Rule {
        /// Access-list name.
        acl: String,
        /// Verdict.
        #[arg(long, value_enum, default_value = "permit")]
        action: VerdictChoice,
        /// Protocol.
        #[arg(long, value_enum)]
        protocol: RuleProtocolChoice,
        /// Source address.
        #[arg(long)]
        source: String,
        /// Source mask (default: one host).
        #[arg(long)]
        source_mask: Option<String>,
        /// Destination address.
        #[arg(long)]
        destination: String,
        /// Destination mask (default: one host).
        #[arg(long)]
        destination_mask: Option<String>,
        /// Source port (TCP and UDP rules only).
        #[arg(long)]
        source_port: Option<u16>,
        /// Destination port (TCP and UDP rules only).
        #[arg(long)]
        port: Option<u16>,
        /// Remove exactly this rule instead.
        #[arg(long)]
        remove: bool,
    },
    /// Describe, disable or schedule the rule at an index.
    #[command(group = clap::ArgGroup::new("property").required(true).multiple(false))]
    RuleProperty {
        /// Access-list name.
        acl: String,
        /// Rule index.
        #[arg(long)]
        index: u32,
        /// Description.
        #[arg(long, group = "property")]
        description: Option<String>,
        /// Disable the rule.
        #[arg(long, group = "property")]
        disable: bool,
        /// Schedule name.
        #[arg(long, group = "property")]
        schedule: Option<String>,
    },
    /// Bind an access list to an interface.
    Bind {
        /// Access-list name.
        acl: String,
        /// Interface name.
        #[arg(long)]
        interface: String,
        /// Direction.
        #[arg(long, value_enum, default_value = "in")]
        direction: AclDirection,
        /// Unbind instead.
        #[arg(long)]
        remove: bool,
    },
}

/// Management listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ListenerChoice {
    /// The web interface and RCI.
    Http,
    /// SSH.
    Ssh,
    /// Telnet.
    Telnet,
}

/// Security levels of a management listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum LevelChoice {
    /// Reachable from public interfaces.
    Public,
    /// Reachable from private interfaces.
    Private,
    /// Restricted to protected interfaces.
    Protected,
}

/// HTTPS settings of the web interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum HttpsChoice {
    /// Serve HTTPS.
    On,
    /// Stop serving HTTPS.
    Off,
    /// Move HTTPS to `--port`.
    Port,
    /// Redirect HTTP to HTTPS.
    Redirect,
    /// Stop redirecting HTTP to HTTPS.
    NoRedirect,
    /// Obtain an ACME certificate.
    AcmeGet,
    /// Revoke the ACME certificate.
    AcmeRevoke,
}

/// Service commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ServicesCommand {
    /// List services.
    List,
    /// Start or stop a service.
    Set {
        /// Service name.
        name: String,
        /// On or off.
        state: Toggle,
    },
    /// Move a management listener to another port.
    Port {
        /// Listener.
        #[arg(value_enum)]
        listener: ListenerChoice,
        /// Port.
        port: u16,
    },
    /// Set a management listener's security level.
    SecurityLevel {
        /// Listener.
        #[arg(value_enum)]
        listener: ListenerChoice,
        /// Level.
        #[arg(value_enum)]
        level: LevelChoice,
    },
    /// Change an HTTPS setting of the web interface.
    Https {
        /// Setting.
        #[arg(value_enum)]
        setting: HttpsChoice,
        /// Port for `port`.
        #[arg(long, required_if_eq("setting", "port"))]
        port: Option<u16>,
    },
}

/// Schedule actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ActionChoice {
    /// Start the controlled resource.
    Start,
    /// Stop the controlled resource.
    Stop,
}

/// Schedule commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SchedulesCommand {
    /// List schedules.
    List,
    /// Create a schedule.
    Create {
        /// Schedule name.
        name: String,
    },
    /// Describe a schedule (one word).
    Describe {
        /// Schedule name.
        name: String,
        /// Description.
        description: String,
    },
    /// Add a timed action to a schedule.
    Action {
        /// Schedule name.
        name: String,
        /// Action.
        #[arg(value_enum)]
        action: ActionChoice,
        /// Minute, 0..=59.
        #[arg(long)]
        minute: u8,
        /// Hour, 0..=23.
        #[arg(long)]
        hour: u8,
        /// Day-of-week field as the router stores it (`dow`).
        #[arg(long)]
        days: u8,
    },
}

/// Proxy upstream protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum UpstreamChoice {
    /// Plain HTTP.
    Http,
    /// HTTPS.
    Https,
    /// HTTP CONNECT.
    Connect,
}

/// Remote-access exposure levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum CloudLevelChoice {
    /// Public exposure.
    Public,
    /// Private-network exposure.
    Private,
}

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
    /// Point a web proxy entry at one LAN host.
    ProxyUpstream {
        /// Proxy name.
        name: String,
        /// Protocol.
        #[arg(long, value_enum)]
        protocol: UpstreamChoice,
        /// LAN host address.
        #[arg(long)]
        host: String,
        /// LAN host port.
        #[arg(long)]
        port: u16,
    },
    /// Set the cloud remote-access exposure.
    CloudLevel {
        /// Level.
        #[arg(value_enum)]
        level: CloudLevelChoice,
    },
}
