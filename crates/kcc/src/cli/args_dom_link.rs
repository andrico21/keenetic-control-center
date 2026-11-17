//! Interface, internet-connection, Wi-Fi and mesh commands.

use core::net::Ipv4Addr;

use clap::{Subcommand, ValueEnum};

use super::{args_dom_admin::LevelChoice, args_domains::Toggle};

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
    /// Set the security zone (a management change when it carries kcc's traffic).
    SecurityLevel {
        /// Interface name.
        name: String,
        /// Zone.
        #[arg(value_enum)]
        level: LevelChoice,
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
    /// Create a connection interface.
    Create {
        /// Interface name, e.g. `PPPoE0`.
        name: String,
    },
    /// Delete a connection interface.
    Delete {
        /// Interface name.
        name: String,
    },
    /// Use a static IPv4 address (a management change when it carries kcc's traffic).
    Static {
        /// Interface name.
        name: String,
        /// Address.
        #[arg(long)]
        address: Ipv4Addr,
        /// Network mask.
        #[arg(long)]
        mask: Ipv4Addr,
    },
    /// Get the address by DHCP (a management change when it carries kcc's traffic).
    Dhcp {
        /// Interface name.
        name: String,
    },
    /// Carry a tunneled connection over another interface.
    ConnectVia {
        /// Interface name.
        name: String,
        /// Underlying interface.
        via: String,
    },
}

/// Wi-Fi encryption modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum EncryptionChoice {
    /// The firmware's default encryption.
    Enable,
    /// WPA2.
    Wpa2,
    /// WPA3.
    Wpa3,
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
    /// Set the encryption mode.
    Encryption {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Mode.
        #[arg(value_enum)]
        mode: EncryptionChoice,
    },
    /// Apply a schedule.
    Schedule {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// Schedule name.
        schedule: String,
    },
    /// Set the channel width, e.g. `20` or `40-above/80`.
    ChannelWidth {
        /// Access point or radio name.
        #[arg(long)]
        ap: String,
        /// Width.
        width: String,
    },
    /// Steer dual-band clients between bands.
    BandSteering {
        /// Access point name.
        #[arg(long)]
        ap: String,
        /// On or off.
        state: Toggle,
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
    /// Adopt a candidate into the mesh.
    Acquire {
        /// Candidate id.
        candidate: String,
    },
    /// Reboot a member (destructive: `--confirm-destructive <router>` and the member id
    /// typed again).
    Reboot {
        /// Member id.
        member: String,
        /// The member id again.
        #[arg(long)]
        confirm_member: String,
    },
}
