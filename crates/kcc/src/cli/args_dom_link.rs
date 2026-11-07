//! Write commands of the interface, internet-connection, Wi-Fi and mesh domains.

use core::net::Ipv4Addr;

use clap::{Subcommand, ValueEnum};

use super::{args_dom_admin::LevelChoice, args_domains::Toggle};

/// More interface commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum InterfacesWriteCommand {
    /// Set the security zone (a management change when it carries kcc's traffic).
    SecurityLevel {
        /// Interface name.
        name: String,
        /// Zone.
        #[arg(value_enum)]
        level: LevelChoice,
    },
}

/// More internet connection commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum WanWriteCommand {
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

/// More Wi-Fi commands; an access point is named by `--ap`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum WifiWriteCommand {
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

/// More mesh commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum MeshWriteCommand {
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
