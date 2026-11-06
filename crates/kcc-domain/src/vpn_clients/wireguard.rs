//! Strict WireGuard configuration parsing with secret-preserving fields.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private parser state and helpers are named after WireGuard syntax"
    )
)]

use alloc::collections::BTreeMap;
use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::SecretString;
use thiserror::Error;

/// Parsed WireGuard interface section.
#[derive(Clone)]
#[non_exhaustive]
pub struct WireGuardInterface {
    /// Imported private key, retained only as a secret.
    pub private_key: Option<SecretString>,
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
            listen_port,
            addresses,
            dns,
            asc,
        } = self;
        f.debug_struct("WireGuardInterface")
            .field("private_key_present", &private_key.is_some())
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
            endpoint,
            allowed_ips,
            persistent_keepalive,
            asc,
        } = self;
        f.debug_struct("WireGuardPeer")
            .field("public_key", public_key)
            .field("preshared_key_present", &preshared_key.is_some())
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

enum Section {
    Interface,
    Peer(usize),
}

#[derive(Default)]
struct InterfaceDraft {
    private_key: Option<SecretString>,
    listen_port: Option<u16>,
    addresses: Option<Vec<String>>,
    dns: Option<Vec<String>>,
    asc: BTreeMap<String, String>,
}

#[derive(Default)]
struct PeerDraft {
    public_key: Option<String>,
    preshared_key: Option<SecretString>,
    endpoint: Option<String>,
    allowed_ips: Option<Vec<String>>,
    persistent_keepalive: Option<u16>,
    asc: BTreeMap<String, String>,
}

/// Parses a strict standard WireGuard configuration.
pub(super) fn parse(text: &str) -> Result<WireGuardConfig, WireGuardParseError> {
    let mut interface: Option<InterfaceDraft> = None;
    let mut peers = Vec::<PeerDraft>::new();
    let mut section: Option<Section> = None;
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = Some(parse_section(
                line,
                line_number,
                &mut interface,
                &mut peers,
            )?);
            continue;
        }
        let (field, value) = line
            .split_once('=')
            .map(|(field, value)| (field.trim(), value.trim()))
            .ok_or_else(|| WireGuardParseError::Malformed {
                line: line_number,
                field: line.to_owned(),
            })?;
        match section.as_ref() {
            Some(Section::Interface) => parse_interface_field(
                interface.as_mut().ok_or(WireGuardParseError::Missing {
                    field: "[Interface]",
                })?,
                field,
                value,
                line_number,
            )?,
            Some(Section::Peer(peer_index)) => {
                let peer = peers
                    .get_mut(*peer_index)
                    .ok_or(WireGuardParseError::Missing { field: "[Peer]" })?;
                parse_peer_field(peer, field, value, line_number)?;
            }
            None => {
                return Err(WireGuardParseError::Malformed {
                    line: line_number,
                    field: field.to_owned(),
                });
            }
        }
    }
    let interface_draft = interface.ok_or(WireGuardParseError::Missing {
        field: "[Interface]",
    })?;
    if peers.is_empty() {
        return Err(WireGuardParseError::Missing { field: "[Peer]" });
    }
    Ok(WireGuardConfig {
        interface: WireGuardInterface {
            private_key: interface_draft.private_key,
            listen_port: interface_draft.listen_port,
            addresses: interface_draft.addresses.unwrap_or_default(),
            dns: interface_draft.dns.unwrap_or_default(),
            asc: interface_draft.asc,
        },
        peers: peers
            .into_iter()
            .map(|peer| {
                Ok(WireGuardPeer {
                    public_key: peer
                        .public_key
                        .ok_or(WireGuardParseError::Missing { field: "PublicKey" })?,
                    preshared_key: peer.preshared_key,
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips.unwrap_or_default(),
                    persistent_keepalive: peer.persistent_keepalive,
                    asc: peer.asc,
                })
            })
            .collect::<Result<Vec<_>, WireGuardParseError>>()?,
    })
}

fn parse_section(
    line: &str,
    line_number: usize,
    interface: &mut Option<InterfaceDraft>,
    peers: &mut Vec<PeerDraft>,
) -> Result<Section, WireGuardParseError> {
    match line {
        "[Interface]" => {
            if interface.is_some() {
                return Err(WireGuardParseError::Duplicate {
                    line: line_number,
                    field: "[Interface]".to_owned(),
                });
            }
            *interface = Some(InterfaceDraft::default());
            Ok(Section::Interface)
        }
        "[Peer]" => {
            peers.push(PeerDraft::default());
            Ok(Section::Peer(peers.len().saturating_sub(1)))
        }
        _ => Err(WireGuardParseError::UnknownSection {
            line: line_number,
            section: line.to_owned(),
        }),
    }
}

fn parse_interface_field(
    draft: &mut InterfaceDraft,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    match field {
        "PrivateKey" => set_secret(&mut draft.private_key, field, value, line),
        "ListenPort" => set_integer(&mut draft.listen_port, field, value, line),
        "Address" => set_list(&mut draft.addresses, field, value, line),
        "DNS" => set_list(&mut draft.dns, field, value, line),
        asc if is_asc_field(asc) => insert_once(&mut draft.asc, asc, value, line),
        _ => Err(WireGuardParseError::UnknownField {
            line,
            field: field.to_owned(),
        }),
    }
}

fn parse_peer_field(
    draft: &mut PeerDraft,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    match field {
        "PublicKey" => set_public_key(&mut draft.public_key, field, value, line),
        "PresharedKey" => set_secret(&mut draft.preshared_key, field, value, line),
        "Endpoint" => set_string(&mut draft.endpoint, field, value, line),
        "AllowedIPs" => set_list(&mut draft.allowed_ips, field, value, line),
        "PersistentKeepalive" => set_integer(&mut draft.persistent_keepalive, field, value, line),
        asc if is_asc_field(asc) => insert_once(&mut draft.asc, asc, value, line),
        _ => Err(WireGuardParseError::UnknownField {
            line,
            field: field.to_owned(),
        }),
    }
}

fn set_secret(
    slot: &mut Option<SecretString>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    validate_key(field, value, line)?;
    if slot.replace(SecretString::from(value.to_owned())).is_some() {
        return Err(duplicate(field, line));
    }
    Ok(())
}

fn set_public_key(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    validate_key(field, value, line)?;
    set_string(slot, field, value, line)
}

fn validate_key(field: &str, value: &str, line: usize) -> Result<(), WireGuardParseError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_error| WireGuardParseError::InvalidKey {
            line,
            field: field.to_owned(),
        })?;
    if decoded.len() != 32 {
        return Err(WireGuardParseError::InvalidKey {
            line,
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn set_integer(
    slot: &mut Option<u16>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_error| WireGuardParseError::InvalidInteger {
            line,
            field: field.to_owned(),
        })?;
    if slot.replace(parsed).is_some() {
        return Err(duplicate(field, line));
    }
    Ok(())
}

fn set_string(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if slot.replace(value.to_owned()).is_some() {
        return Err(duplicate(field, line));
    }
    Ok(())
}

fn set_list(
    slot: &mut Option<Vec<String>>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if slot
        .replace(value.split(',').map(str::trim).map(str::to_owned).collect())
        .is_some()
    {
        return Err(duplicate(field, line));
    }
    Ok(())
}

fn insert_once(
    fields: &mut BTreeMap<String, String>,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    if fields.insert(field.to_owned(), value.to_owned()).is_some() {
        return Err(duplicate(field, line));
    }
    Ok(())
}

const fn is_asc_field(field: &str) -> bool {
    matches!(
        field.as_bytes(),
        b"Jc"
            | b"Jmin"
            | b"Jmax"
            | b"S1"
            | b"S2"
            | b"S3"
            | b"S4"
            | b"H1"
            | b"H2"
            | b"H3"
            | b"H4"
            | b"I1"
            | b"I2"
            | b"I3"
            | b"I4"
            | b"I5"
    )
}

fn duplicate(field: &str, line: usize) -> WireGuardParseError {
    WireGuardParseError::Duplicate {
        line,
        field: field.to_owned(),
    }
}
