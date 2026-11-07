//! Secret-preserving WireGuard import types.

use alloc::collections::BTreeMap;
use core::fmt;

use secrecy::SecretString;
use thiserror::Error;

/// Parsed WireGuard interface section.
#[derive(Clone)]
#[non_exhaustive]
pub struct WireGuardInterface {
    /// Imported private key, retained only as a secret.
    pub private_key: Option<SecretString>,
    /// Optional `ObfsKey`, retained only as a secret.
    pub obfuscation_key: Option<SecretString>,
    /// Optional listen port.
    pub listen_port: Option<u16>,
    /// Interface addresses.
    pub addresses: Vec<String>,
    /// Interface DNS servers.
    pub dns: Vec<String>,
    /// Optional ASC fields keyed by canonical field name.
    pub asc: BTreeMap<String, String>,
}

impl fmt::Debug for WireGuardInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            private_key,
            obfuscation_key,
            listen_port,
            addresses,
            dns,
            asc,
        } = self;
        f.debug_struct("WireGuardInterface")
            .field("private_key_present", &private_key.is_some())
            .field("obfuscation_key_present", &obfuscation_key.is_some())
            .field("listen_port", listen_port)
            .field("addresses", addresses)
            .field("dns", dns)
            .field("asc", asc)
            .finish()
    }
}

/// Parsed WireGuard peer section.
#[derive(Clone)]
#[non_exhaustive]
pub struct WireGuardPeer {
    /// Peer public key.
    pub public_key: String,
    /// Optional preshared key, retained only as a secret.
    pub preshared_key: Option<SecretString>,
    /// Optional `ObfsKey`, retained only as a secret.
    pub obfuscation_key: Option<SecretString>,
    /// Optional endpoint.
    pub endpoint: Option<String>,
    /// Allowed IP prefixes.
    pub allowed_ips: Vec<String>,
    /// Optional keepalive interval.
    pub persistent_keepalive: Option<u16>,
    /// Optional peer ASC fields keyed by canonical field name.
    pub asc: BTreeMap<String, String>,
}

impl fmt::Debug for WireGuardPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            public_key,
            preshared_key,
            obfuscation_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
            asc,
        } = self;
        f.debug_struct("WireGuardPeer")
            .field("public_key", public_key)
            .field("preshared_key_present", &preshared_key.is_some())
            .field("obfuscation_key_present", &obfuscation_key.is_some())
            .field("endpoint", endpoint)
            .field("allowed_ips", allowed_ips)
            .field("persistent_keepalive", persistent_keepalive)
            .field("asc", asc)
            .finish()
    }
}

/// Parsed WireGuard configuration.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WireGuardConfig {
    /// Single interface section.
    pub interface: WireGuardInterface,
    /// One or more peer sections.
    pub peers: Vec<WireGuardPeer>,
}

/// Field-level WireGuard parse failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum WireGuardParseError {
    /// A required section is missing.
    #[error("WireGuard field {field} is required")]
    Missing {
        /// Missing section or field.
        field: &'static str,
    },
    /// A section name is unsupported.
    #[error("unknown WireGuard section at line {line}")]
    UnknownSection {
        /// Source line.
        line: usize,
        /// Unsupported section name.
        section: String,
    },
    /// A field is unsupported in its section.
    #[error("unknown WireGuard field {field} at line {line}")]
    UnknownField {
        /// Source line.
        line: usize,
        /// Unsupported field name.
        field: String,
    },
    /// A section or field occurs more than allowed.
    #[error("duplicate WireGuard field {field} at line {line}")]
    Duplicate {
        /// Source line.
        line: usize,
        /// Duplicated section or field.
        field: String,
    },
    /// A line is not a key/value assignment.
    #[error("malformed WireGuard field at line {line}")]
    Malformed {
        /// Source line.
        line: usize,
        /// Field associated with the error.
        field: String,
    },
    /// A key is not exactly 32 Base64-decoded bytes.
    #[error("invalid WireGuard key in field {field} at line {line}")]
    InvalidKey {
        /// Source line.
        line: usize,
        /// Invalid key field.
        field: String,
    },
    /// An integer field is malformed.
    #[error("invalid WireGuard integer in field {field} at line {line}")]
    InvalidInteger {
        /// Source line.
        line: usize,
        /// Invalid integer field.
        field: String,
    },
}
