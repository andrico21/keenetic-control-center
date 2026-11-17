//! Strict WireGuard section parsing.

use alloc::collections::BTreeMap;

use secrecy::SecretString;

use super::{
    wireguard::{WireGuardConfig, WireGuardInterface, WireGuardParseError, WireGuardPeer},
    wireguard_fields::{
        insert_once, is_asc_field, set_integer, set_list, set_obfuscation, set_public_key,
        set_secret, set_string,
    },
};

/// The section the parser is in.
enum Section {
    /// The `[Interface]` section.
    Interface,
    /// The `[Peer]` section with this index.
    Peer(usize),
}

/// The `[Interface]` fields read so far.
#[derive(Default)]
struct InterfaceDraft {
    /// `PrivateKey`.
    private_key: Option<SecretString>,
    /// `ObfsKey`.
    obfuscation_key: Option<SecretString>,
    /// `ListenPort`.
    listen_port: Option<u16>,
    /// `Address`.
    addresses: Option<Vec<String>>,
    /// `DNS`.
    dns: Option<Vec<String>>,
    /// The ASC values by name.
    asc: BTreeMap<String, String>,
}

/// The fields of one `[Peer]` read so far.
#[derive(Default)]
struct PeerDraft {
    /// `PublicKey`.
    public_key: Option<String>,
    /// `PresharedKey`.
    preshared_key: Option<SecretString>,
    /// `ObfsKey`.
    obfuscation_key: Option<SecretString>,
    /// `Endpoint`.
    endpoint: Option<String>,
    /// `AllowedIPs`.
    allowed_ips: Option<Vec<String>>,
    /// `PersistentKeepalive`.
    persistent_keepalive: Option<u16>,
    /// The ASC values by name.
    asc: BTreeMap<String, String>,
}

/// Parses a strict standard WireGuard configuration.
///
/// # Errors
///
/// Returns the first parse failure met, reading line by line: [`WireGuardParseError::Malformed`]
/// for a line that is not `key = value`, that precedes every section, or for an empty, over-long
/// or control-character `ObfsKey`; [`WireGuardParseError::UnknownSection`] and
/// [`WireGuardParseError::UnknownField`] for a name the format does not have;
/// [`WireGuardParseError::Duplicate`] for a repeated `[Interface]` section or field;
/// [`WireGuardParseError::InvalidKey`] for a key that is not Base64 of 32 bytes;
/// [`WireGuardParseError::InvalidInteger`] for a port or keepalive that is not a 16-bit number;
/// and [`WireGuardParseError::Missing`] when `[Interface]`, `[Peer]` or a peer's `PublicKey` is
/// absent.
pub(crate) fn parse(text: &str) -> Result<WireGuardConfig, WireGuardParseError> {
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
            .ok_or(WireGuardParseError::Malformed { line: line_number })?;
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
                return Err(WireGuardParseError::Malformed { line: line_number });
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
            obfuscation_key: interface_draft.obfuscation_key,
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
                    obfuscation_key: peer.obfuscation_key,
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips.unwrap_or_default(),
                    persistent_keepalive: peer.persistent_keepalive,
                    asc: peer.asc,
                })
            })
            .collect::<Result<Vec<_>, WireGuardParseError>>()?,
    })
}

/// Opens the section a `[Interface]` or `[Peer]` header line starts.
///
/// # Errors
///
/// Returns [`WireGuardParseError`] for an unknown section or a second `[Interface]`.
fn parse_section(
    line: &str,
    line_number: usize,
    interface: &mut Option<InterfaceDraft>,
    peers: &mut Vec<PeerDraft>,
) -> Result<Section, WireGuardParseError> {
    match line {
        "[Interface]" => {
            if interface.is_some() {
                return Err(WireGuardParseError::Duplicate { line: line_number });
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

/// Reads one `[Interface]` field into its draft.
///
/// # Errors
///
/// Returns [`WireGuardParseError`] for an unknown, repeated or malformed field.
fn parse_interface_field(
    draft: &mut InterfaceDraft,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    match field {
        "PrivateKey" => set_secret(&mut draft.private_key, field, value, line),
        "ObfsKey" => set_obfuscation(&mut draft.obfuscation_key, value, line),
        "ListenPort" => set_integer(&mut draft.listen_port, field, value, line),
        "Address" => set_list(&mut draft.addresses, value, line),
        "DNS" => set_list(&mut draft.dns, value, line),
        asc if is_asc_field(asc) => insert_once(&mut draft.asc, asc, value, line),
        _ => Err(WireGuardParseError::UnknownField { line }),
    }
}

/// Reads one `[Peer]` field into its draft.
///
/// # Errors
///
/// Returns [`WireGuardParseError`] for an unknown, repeated or malformed field.
fn parse_peer_field(
    draft: &mut PeerDraft,
    field: &str,
    value: &str,
    line: usize,
) -> Result<(), WireGuardParseError> {
    match field {
        "PublicKey" => set_public_key(&mut draft.public_key, field, value, line),
        "PresharedKey" => set_secret(&mut draft.preshared_key, field, value, line),
        "ObfsKey" => set_obfuscation(&mut draft.obfuscation_key, value, line),
        "Endpoint" => set_string(&mut draft.endpoint, value, line),
        "AllowedIPs" => set_list(&mut draft.allowed_ips, value, line),
        "PersistentKeepalive" => set_integer(&mut draft.persistent_keepalive, field, value, line),
        asc if is_asc_field(asc) => insert_once(&mut draft.asc, asc, value, line),
        _ => Err(WireGuardParseError::UnknownField { line }),
    }
}
