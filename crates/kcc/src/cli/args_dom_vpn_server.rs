//! VPN server commands; keys and passwords come only from `--password-file`,
//! `KCC_PASSWORD` or a hidden prompt.

use clap::{Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// VPN server services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ServiceKind {
    /// The PPTP/L2TP server.
    Vpn,
    /// The SSTP server.
    Sstp,
    /// The IPsec/IKEv2 server.
    Ipsec,
    /// The OpenConnect server.
    Openconnect,
}

/// VPN servers with an interface and a client address pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum PoolServer {
    /// The PPTP/L2TP server.
    Vpn,
    /// The SSTP server.
    Sstp,
    /// The OpenConnect server.
    Openconnect,
}

/// VPN server commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum VpnServerCommand {
    /// VPN server configuration and state.
    Status,
    /// Start or stop a VPN server service.
    Service {
        /// Service.
        #[arg(value_enum)]
        service: ServiceKind,
        /// On or off.
        state: Toggle,
    },
    /// Bind a VPN server to an interface.
    Interface {
        /// Server.
        #[arg(long, value_enum)]
        server: PoolServer,
        /// Interface name.
        interface: String,
    },
    /// Set a VPN server's client address pool.
    Pool {
        /// Server.
        #[arg(long, value_enum)]
        server: PoolServer,
        /// First address.
        begin: String,
        /// Number of addresses.
        #[arg(long)]
        size: Option<u16>,
    },
    /// Serve WireGuard on an interface.
    WireguardInterface {
        /// Interface name.
        interface: String,
        /// On or off.
        state: Toggle,
    },
    /// Hand out virtual IPs on an IPsec crypto map.
    IpsecVirtualIp {
        /// Crypto map name.
        map: String,
        /// On or off.
        state: Toggle,
    },
    /// Set the IPsec/IKEv2 server's IKE key (from `--password-file`, `KCC_PASSWORD` or a
    /// hidden prompt).
    IkePsk {
        /// IKE key name.
        name: String,
    },
    /// Set a VPN user's password (management change; from `--password-file`,
    /// `KCC_PASSWORD` or a hidden prompt).
    Password {
        /// Router account name.
        user: String,
    },
}
