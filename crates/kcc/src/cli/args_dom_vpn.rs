//! VPN client write commands; secrets come only from `--password-file`, `KCC_PASSWORD`
//! or a hidden prompt, and a WireGuard import reads its `.conf` from `--file`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// Tunnels whose routes the server may push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum RoutesKind {
    /// A ZeroTier network.
    Zerotier,
    /// An OpenVPN tunnel.
    Openvpn,
}

/// Tunnels with a selectable protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ProtocolKind {
    /// An OpenConnect tunnel.
    Openconnect,
    /// A proxy connection.
    Proxy,
}

/// Named crypto objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum CryptoKind {
    /// An IKE policy.
    IkePolicy,
    /// An IKE proposal.
    IkeProposal,
    /// An IPsec profile.
    IpsecProfile,
    /// An IPsec transform set.
    IpsecTransform,
    /// A crypto map.
    CryptoMap,
}

/// VPN credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SecretKind {
    /// The PPP password of an L2TP, PPTP or SSTP tunnel.
    Ppp,
    /// The IPsec pre-shared key of a tunnel interface.
    Ipsec,
    /// A named IKE key.
    Ike,
    /// The pre-shared key of an IPsec profile.
    ProfilePsk,
    /// The `XAuth` password of an IPsec profile.
    ProfileXauth,
}

/// VPN client commands that change the configuration.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum VpnWriteCommand {
    /// Create a tunnel interface, e.g. `Wireguard1`.
    Create {
        /// Interface name.
        name: String,
    },
    /// Delete a tunnel interface.
    Delete {
        /// Interface name.
        name: String,
    },
    /// Turn a tunnel on or off.
    Enable {
        /// Interface name.
        name: String,
        /// On or off.
        state: Toggle,
    },
    /// Let the router generate a WireGuard private key.
    WireguardGenerateKey {
        /// Interface name.
        name: String,
    },
    /// Set the WireGuard listen port.
    WireguardListenPort {
        /// Interface name.
        name: String,
        /// Port.
        port: u16,
    },
    /// Add a WireGuard peer.
    WireguardPeer {
        /// Interface name.
        name: String,
        /// Peer public key.
        #[arg(long)]
        public_key: String,
    },
    /// Set a WireGuard peer's endpoint.
    WireguardEndpoint {
        /// Interface name.
        name: String,
        /// Peer public key.
        #[arg(long)]
        public_key: String,
        /// Endpoint host.
        #[arg(long)]
        address: String,
        /// Endpoint port.
        #[arg(long)]
        port: u16,
    },
    /// Add an allowed network to a WireGuard peer.
    WireguardAllowedIp {
        /// Interface name.
        name: String,
        /// Peer public key.
        #[arg(long)]
        public_key: String,
        /// Network address.
        #[arg(long)]
        address: String,
        /// Network mask.
        #[arg(long)]
        mask: String,
    },
    /// Set a WireGuard peer's keepalive interval.
    WireguardKeepalive {
        /// Interface name.
        name: String,
        /// Peer public key.
        #[arg(long)]
        public_key: String,
        /// Seconds.
        #[arg(long)]
        seconds: u16,
    },
    /// Set WireGuard ASC parameters in router order (jc jmin jmax s1 s2 h1..h4 s3 s4 i1..i5).
    WireguardAsc {
        /// Interface name.
        name: String,
        /// Parameter values.
        #[arg(required = true, num_args = 1..=16)]
        values: Vec<String>,
    },
    /// Join a ZeroTier network.
    ZerotierNetwork {
        /// Interface name.
        name: String,
        /// Network id.
        network_id: String,
    },
    /// Accept or refuse the routes a ZeroTier or OpenVPN server pushes.
    AcceptRoutes {
        /// Interface name.
        name: String,
        /// Tunnel kind.
        #[arg(long, value_enum)]
        kind: RoutesKind,
        /// On or off.
        state: Toggle,
    },
    /// Set the protocol of an OpenConnect tunnel or a proxy connection.
    Protocol {
        /// Interface name.
        name: String,
        /// Tunnel kind.
        #[arg(long, value_enum)]
        kind: ProtocolKind,
        /// Protocol.
        protocol: String,
    },
    /// Set a proxy connection's upstream.
    ProxyUpstream {
        /// Interface name.
        name: String,
        /// Upstream host.
        #[arg(long)]
        host: String,
        /// Upstream port.
        #[arg(long)]
        port: Option<u16>,
    },
    /// Create a named crypto object.
    Crypto {
        /// Object kind.
        #[arg(value_enum)]
        kind: CryptoKind,
        /// Object name.
        name: String,
    },
}

/// VPN client commands that carry key material: never on the command line.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum VpnSecretCommand {
    /// Create a WireGuard tunnel from a `.conf` file (keys stay out of argv and output).
    WireguardImport {
        /// New interface name; an existing name is refused.
        name: String,
        /// The WireGuard configuration file.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
    /// Set a VPN credential (from `--password-file`, `KCC_PASSWORD` or a hidden prompt).
    Secret {
        /// Credential kind.
        #[arg(value_enum)]
        kind: SecretKind,
        /// Interface, IKE key or IPsec profile name.
        name: String,
    },
}
