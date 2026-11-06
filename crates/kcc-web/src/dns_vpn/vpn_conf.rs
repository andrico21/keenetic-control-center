//! What a WireGuard `.conf` file says to the import: the connection's name and the parsed
//! file, the field errors that stop it, and the notes on what the router does not get.
//!
//! An error names a line and a WireGuard field, never a value taken from the file.

use fluent_bundle::FluentArgs;
use kcc_domain::vpn_clients::{
    self,
    wireguard::{WireGuardConfig, WireGuardParseError},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use secrecy::{ExposeSecret as _, SecretString};

use super::check;

/// WireGuard field and section names a parse error may name back to the user.
const NAMED: [&str; 27] = [
    "[Interface]",
    "[Peer]",
    "PrivateKey",
    "PublicKey",
    "PresharedKey",
    "ListenPort",
    "Address",
    "DNS",
    "Endpoint",
    "AllowedIPs",
    "PersistentKeepalive",
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
];

/// The connection's name and the parsed file, or the field errors that stop the import.
///
/// # Errors
///
/// Returns each problem with the field it belongs to.
pub(crate) fn checked(
    (typed, file): (&str, Option<&SecretString>),
    locale: Locale,
) -> Result<(String, WireGuardConfig), Vec<(&'static str, String)>> {
    let name = check::tunnel(typed);
    let parsed = file.map(|text| vpn_clients::parse_wireguard_config(text.expose_secret()));
    let mut problems = Vec::new();
    if name.is_none() {
        problems.push(("name", tr(locale, keys::WEB_VPN_ERROR_NAME, None)));
    }
    match parsed {
        None => problems.push(("file", tr(locale, keys::WEB_VPN_ERROR_NO_FILE, None))),
        Some(Err(error)) => problems.push(("file", parse_error(locale, &error))),
        Some(Ok(config)) => {
            problems.extend(
                routable(&config, locale)
                    .into_iter()
                    .map(|text| ("file", text)),
            );
            if let (Some(valid), true) = (name, problems.is_empty()) {
                return Ok((valid, config));
            }
        }
    }
    Err(problems)
}

/// The parse error as a sentence naming its line and field, never a value of the file.
fn parse_error(locale: Locale, error: &WireGuardParseError) -> String {
    let mut args = FluentArgs::new();
    let named = |field: &str| NAMED.contains(&field).then(|| field.to_owned());
    let key = match error {
        WireGuardParseError::Missing { field } => {
            args.set("field", (*field).to_owned());
            keys::WEB_VPN_CONF_MISSING
        }
        WireGuardParseError::UnknownSection { line, section: _ } => {
            args.set("line", *line);
            keys::WEB_VPN_CONF_UNKNOWN_SECTION
        }
        WireGuardParseError::UnknownField { line, field: _ } => {
            args.set("line", *line);
            keys::WEB_VPN_CONF_UNKNOWN_FIELD
        }
        WireGuardParseError::Malformed { line, field: _ } => {
            args.set("line", *line);
            keys::WEB_VPN_CONF_MALFORMED
        }
        WireGuardParseError::Duplicate { line, field }
        | WireGuardParseError::InvalidKey { line, field }
        | WireGuardParseError::InvalidInteger { line, field } => {
            args.set("line", *line);
            match (named(field), error) {
                (Some(known), WireGuardParseError::Duplicate { line: _, field: _ }) => {
                    args.set("field", known);
                    keys::WEB_VPN_CONF_DUPLICATE
                }
                (Some(known), WireGuardParseError::InvalidKey { line: _, field: _ }) => {
                    args.set("field", known);
                    keys::WEB_VPN_CONF_KEY
                }
                (Some(known), _) => {
                    args.set("field", known);
                    keys::WEB_VPN_CONF_NUMBER
                }
                (None, _) => keys::WEB_VPN_CONF_UNKNOWN_FIELD,
            }
        }
        _ => keys::WEB_VPN_CONF_INVALID,
    };
    tr(locale, key, Some(&args))
}

/// What the router cannot take from a parsed file: IPv6 or malformed allowed ranges, and
/// endpoints given by host name; each finding names its `[Peer]` by number.
fn routable(config: &WireGuardConfig, locale: Locale) -> Vec<String> {
    let mut problems = Vec::new();
    for (index, peer) in config.peers.iter().enumerate() {
        let mut args = FluentArgs::new();
        args.set("peer", index.saturating_add(1));
        if peer
            .allowed_ips
            .iter()
            .any(|range| check::ipv4_range(range).is_none())
        {
            problems.push(tr(locale, keys::WEB_VPN_CONF_ALLOWED, Some(&args)));
        }
        if peer
            .endpoint
            .as_deref()
            .is_some_and(|endpoint| check::endpoint(endpoint).is_none())
        {
            problems.push(tr(locale, keys::WEB_VPN_CONF_ENDPOINT, Some(&args)));
        }
    }
    problems
}

/// What the import leaves out of the file, as notes for the outcome.
pub(crate) fn skipped(config: &WireGuardConfig, locale: Locale) -> Vec<String> {
    let interface = &config.interface;
    let peers = &config.peers;
    let left: [(bool, MessageKey); 5] = [
        (
            interface.private_key.is_some(),
            keys::WEB_VPN_SKIP_PRIVATE_KEY,
        ),
        (
            peers.iter().any(|peer| peer.preshared_key.is_some()),
            keys::WEB_VPN_SKIP_PRESHARED_KEY,
        ),
        (!interface.addresses.is_empty(), keys::WEB_VPN_SKIP_ADDRESS),
        (!interface.dns.is_empty(), keys::WEB_VPN_SKIP_DNS),
        (
            !interface.asc.is_empty() || peers.iter().any(|peer| !peer.asc.is_empty()),
            keys::WEB_VPN_SKIP_ASC,
        ),
    ];
    left.into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, key)| tr(locale, key, None))
        .collect()
}
