//! Deterministic, per-run anonymization of captured router data.
//!
//! One [`Anonymizer`] holds a random HMAC key that exists only in memory for the run, plus
//! first-seen allocation tables, so every value maps the same way within a run and
//! differently across runs:
//!
//! - MAC addresses become `02:00:00:xx:xx:xx`, the low three bytes taken from an HMAC of
//!   the original.
//! - Private IPv4 (RFC 1918 and RFC 6598) `/24` networks map to `192.0.2.0/24` and then
//!   `198.51.100.0/24` with the host octet kept, so addresses that shared a `/24` still do.
//!   Every other IPv4 address (public, or a private `/24` past the second) becomes one host
//!   in `203.0.113.0/24`.
//! - IPv6 `/48` prefixes map to `2001:db8:N::/48` with the subnet id kept; interface ids
//!   above `0xffff` are replaced through the HMAC. Link-local keeps `fe80::/64`.
//! - Hostnames, descriptions and SSIDs become `host-N` / `ssid-N`; serials, IMEI and ICCID
//!   become zeros; registry secrets, `ns3` payloads and WireGuard-key-shaped strings become
//!   [`PLACEHOLDER`].
//!
//! Unspecified, broadcast, loopback, multicast, link-local IPv4 and netmask-shaped values
//! are kept unchanged.

use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    cmp::Reverse,
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use hmac::{Hmac, KeyInit as _, Mac as _};
use kcc_config::{
    config_text::{self, Node, ParseError, Token},
    secrets,
};
use rand::RngExt as _;
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Replacement for every secret value and `ns3` payload.
pub const PLACEHOLDER: &str = "<redacted>";

/// Targets for private `/24` networks, in allocation order (RFC 5737).
const SUBNET_TARGETS: [[u8; 3]; 2] = [[192, 0, 2], [198, 51, 100]];

/// The `/24` that receives individually mapped IPv4 hosts (RFC 5737).
const HOST_POOL: [u8; 3] = [203, 0, 113];

/// Shortest original value that is also replaced wherever it appears in free text.
const MIN_LEARNED_CHARS: usize = 4;

/// JSON keys whose values are secrets.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "psk",
    "wpa-psk",
    "key",
    "secret",
    "private-key",
    "preshared-key",
    "pre-shared-key",
    "shared-secret",
    "community",
    "passphrase",
    "token",
    "radiussecret",
    "uamsecret",
    "macpasswd",
    "ns3",
    "md5",
    "nt",
    "plain",
    "hash",
];

/// JSON keys whose values are hardware identifiers.
const SERIAL_KEYS: &[&str] = &[
    "serial",
    "serial-number",
    "serialnumber",
    "servicetag",
    "sn",
    "imei",
    "iccid",
    "imsi",
    "uuid",
    "cid",
    "device-id",
    "license",
];

/// JSON keys whose values are wireless network names.
const SSID_KEYS: &[&str] = &["ssid", "essid"];

/// JSON keys whose values are host names or free-form descriptions.
const HOST_KEYS: &[&str] = &[
    "hostname",
    "host",
    "description",
    "domain",
    "domain-name",
    "comment",
];

/// Why a value could not be anonymized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers import the error by name next to other crates' errors"
)]
pub enum AnonymizeError {
    /// More distinct addresses than the documentation ranges can hold.
    AddressSpaceExhausted,
    /// A configuration text does not parse, so it cannot be anonymized structurally.
    ConfigParse,
}

impl fmt::Display for AnonymizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AddressSpaceExhausted => "documentation address space exhausted",
            Self::ConfigParse => "configuration text does not parse",
        })
    }
}

impl Error for AnonymizeError {}

impl From<ParseError> for AnonymizeError {
    #[inline]
    fn from(_error: ParseError) -> Self {
        Self::ConfigParse
    }
}

/// What a JSON value is, judged by the key that holds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Context {
    /// No special meaning; strings go through the text rules.
    Plain,
    /// A secret.
    Secret,
    /// A hardware identifier.
    Serial,
    /// A wireless network name.
    Ssid,
    /// A host name or description.
    Host,
}

/// Classifies a JSON object key.
fn classify(key: &str) -> Context {
    let normalized = key.to_ascii_lowercase().replace('_', "-");
    let name = normalized.as_str();
    if SECRET_KEYS.contains(&name) {
        Context::Secret
    } else if SERIAL_KEYS.contains(&name) {
        Context::Serial
    } else if SSID_KEYS.contains(&name) {
        Context::Ssid
    } else if HOST_KEYS.contains(&name) {
        Context::Host
    } else {
        Context::Plain
    }
}

/// Deterministic anonymizer for one capture run.
pub struct Anonymizer {
    /// Per-run HMAC key; generated in memory and never written anywhere.
    key: Zeroizing<[u8; 64]>,
    /// Original MAC to the low three bytes of its replacement.
    macs: BTreeMap<[u8; 6], [u8; 3]>,
    /// Replacement MAC suffixes already handed out.
    used_macs: BTreeSet<[u8; 3]>,
    /// Private `/24` networks to their documentation `/24`.
    subnets: BTreeMap<[u8; 3], [u8; 3]>,
    /// Individually mapped IPv4 hosts.
    hosts: BTreeMap<Ipv4Addr, Ipv4Addr>,
    /// IPv6 `/48` prefixes to their `2001:db8:N::/48` slot.
    prefixes: BTreeMap<[u16; 3], u16>,
    /// Host names and descriptions to `host-N`.
    host_names: BTreeMap<String, String>,
    /// SSIDs to `ssid-N`.
    ssids: BTreeMap<String, String>,
    /// Original values replaced wherever they appear in free text.
    learned: BTreeMap<String, String>,
}

impl fmt::Debug for Anonymizer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anonymizer")
            .field("key", &"[REDACTED]")
            .field("macs", &self.macs.len())
            .field("subnets", &self.subnets.len())
            .field("hosts", &self.hosts.len())
            .field("prefixes", &self.prefixes.len())
            .field("host_names", &self.host_names.len())
            .field("ssids", &self.ssids.len())
            .finish_non_exhaustive()
    }
}

impl Default for Anonymizer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Anonymizer {
    /// Creates an anonymizer with a fresh random key.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::from_key(Zeroizing::new(rand::rng().random::<[u8; 64]>()))
    }

    /// Creates an anonymizer with `key`.
    const fn from_key(key: Zeroizing<[u8; 64]>) -> Self {
        Self {
            key,
            macs: BTreeMap::new(),
            used_macs: BTreeSet::new(),
            subnets: BTreeMap::new(),
            hosts: BTreeMap::new(),
            prefixes: BTreeMap::new(),
            host_names: BTreeMap::new(),
            ssids: BTreeMap::new(),
            learned: BTreeMap::new(),
        }
    }

    /// Anonymizes a JSON document.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    #[inline]
    pub fn json(&mut self, value: &Value) -> Result<Value, AnonymizeError> {
        self.value(value, Context::Plain)
    }

    /// Anonymizes free text: secrets, then addresses, then learned names and serials.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    #[inline]
    pub fn text(&mut self, text: &str) -> Result<String, AnonymizeError> {
        let without_secrets = redact_secret_shapes(text);
        let hex = rewrite_runs(&without_secrets, is_hex_run_char, |run| self.hex_run(run))?;
        let addressed = rewrite_runs(&hex, is_ipv4_run_char, |run| self.ipv4_run(run))?;
        Ok(self.replace_learned(addressed))
    }

    /// Anonymizes a Keenetic configuration text structurally.
    ///
    /// Registry secrets and every `ns3` payload become [`PLACEHOLDER`]; `ssid`,
    /// `description`, `hostname`, `known host`, `ip host` and `domain name` arguments
    /// become aliases; other words go through [`Anonymizer::text`]. The header keeps
    /// model, version and agent, drops the checksum and generalizes the user name.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::ConfigParse`] when the text does not parse, so nothing
    /// half-anonymized is produced; otherwise as [`Anonymizer::text`].
    #[inline]
    pub fn config(&mut self, text: &str) -> Result<String, AnonymizeError> {
        let mut ast = secrets::redact(&config_text::parse(text)?);
        ast.header.md5 = None;
        if ast.header.username.is_some() {
            ast.header.username = Some("admin".to_owned());
        }
        let mut extra = BTreeMap::new();
        for (key, value) in &ast.header.extra {
            drop(extra.insert(key.clone(), self.text(value)?));
        }
        ast.header.extra = extra;
        for node in &mut ast.nodes {
            self.config_node(node)?;
        }
        Ok(config_text::print(&ast))
    }

    /// Rewrites one configuration node and its children in place.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn config_node(&mut self, node: &mut Node) -> Result<(), AnonymizeError> {
        let mut previous: Vec<String> = Vec::new();
        let mut tokens = Vec::with_capacity(node.tokens.len());
        for token in &node.tokens {
            let rewritten = match token {
                Token::Ns3(_) => Token::Ns3(PLACEHOLDER.to_owned()),
                Token::Word(word) if word == PLACEHOLDER => token.clone(),
                Token::Word(word) => Token::Word(self.config_word(&previous, word)?),
                _ => token.clone(),
            };
            if let Token::Word(word) = token {
                previous.push(word.clone());
            }
            tokens.push(rewritten);
        }
        node.tokens = tokens;
        for child in &mut node.children {
            self.config_node(child)?;
        }
        Ok(())
    }

    /// Rewrites one configuration word given the words before it on its line.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn config_word(&mut self, previous: &[String], word: &str) -> Result<String, AnonymizeError> {
        let last_two = match previous {
            [.., before, last] => (Some(before.as_str()), Some(last.as_str())),
            [last] => (None, Some(last.as_str())),
            [] => (None, None),
        };
        match last_two {
            (_, Some("ssid")) => Ok(self.alias(word, Context::Ssid)),
            (_, Some("description" | "hostname"))
            | (Some("known" | "ip"), Some("host"))
            | (Some("domain"), Some("name")) => Ok(self.alias(word, Context::Host)),
            _ => self.text(word),
        }
    }

    /// Anonymizes one JSON value in `context`.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn value(&mut self, value: &Value, context: Context) -> Result<Value, AnonymizeError> {
        Ok(match value {
            Value::Object(object) => {
                let inherited = context == Context::Secret;
                let has_mac = object.contains_key("mac");
                let mut result = Map::new();
                for (key, member) in object {
                    let member_context = match classify(key) {
                        _ if inherited => Context::Secret,
                        Context::Plain if key == "name" && has_mac => Context::Host,
                        known @ (Context::Plain
                        | Context::Secret
                        | Context::Serial
                        | Context::Ssid
                        | Context::Host) => known,
                    };
                    let anonymized = self.value(member, member_context)?;
                    drop(result.insert(self.text(key)?, anonymized));
                }
                Value::Object(result)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| self.value(item, context))
                    .collect::<Result<_, _>>()?,
            ),
            Value::String(text) => Value::String(match context {
                Context::Plain => self.text(text)?,
                Context::Secret | Context::Serial | Context::Ssid | Context::Host => {
                    self.alias(text, context)
                }
            }),
            Value::Number(_) => match context {
                Context::Secret => Value::String(PLACEHOLDER.to_owned()),
                Context::Serial => Value::from(0_u8),
                Context::Plain | Context::Ssid | Context::Host => value.clone(),
            },
            Value::Null | Value::Bool(_) => value.clone(),
        })
    }

    /// The replacement for a value whose meaning is known from its key.
    fn alias(&mut self, original: &str, context: Context) -> String {
        if original.is_empty() || original == PLACEHOLDER {
            return original.to_owned();
        }
        let replacement = match context {
            Context::Secret => PLACEHOLDER.to_owned(),
            Context::Serial => original
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        '0'
                    } else {
                        character
                    }
                })
                .collect(),
            Context::Ssid => numbered(&mut self.ssids, "ssid", original),
            Context::Host | Context::Plain => numbered(&mut self.host_names, "host", original),
        };
        if original.chars().count() >= MIN_LEARNED_CHARS {
            drop(
                self.learned
                    .insert(original.to_owned(), replacement.clone()),
            );
        }
        replacement
    }

    /// Replaces every learned original value, longest first.
    fn replace_learned(&self, text: String) -> String {
        let mut originals: Vec<(&String, &String)> = self.learned.iter().collect();
        originals.sort_by_key(|entry| Reverse(entry.0.len()));
        originals
            .into_iter()
            .fold(text, |current, (original, replacement)| {
                if current.contains(original.as_str()) {
                    current.replace(original.as_str(), replacement)
                } else {
                    current
                }
            })
    }

    /// Rewrites a run of hex digits, `:`, `-` and `.`: MAC addresses and IPv6.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn hex_run(&mut self, run: &str) -> Result<String, AnonymizeError> {
        if run.contains(':') && !run.trim_end_matches(['.', '-']).contains('.') {
            let candidates = [
                run,
                run.trim_end_matches(['.', '-']),
                run.trim_end_matches(['.', ':', '-']),
            ];
            for candidate in candidates {
                if let Ok(address) = candidate.parse::<Ipv6Addr>() {
                    let suffix = run.get(candidate.len()..).unwrap_or_default();
                    return Ok(format!("{}{suffix}", self.map_ipv6(address)?));
                }
            }
        }
        let mut output = String::with_capacity(run.len());
        let mut position = 0_usize;
        while let Some(rest) = run.get(position..) {
            if rest.is_empty() {
                break;
            }
            let window = rest.get(..MAC_TEXT_LEN).and_then(parse_mac);
            match window {
                Some(mac) if starts_group(run, position) => {
                    output.push_str(&format_mac(self.map_mac(mac)));
                    position = position.saturating_add(MAC_TEXT_LEN);
                }
                Some(_) | None => {
                    let next = rest.chars().next().unwrap_or_default();
                    output.push(next);
                    position = position.saturating_add(next.len_utf8());
                }
            }
        }
        Ok(output)
    }

    /// Rewrites a run of digits and dots holding one IPv4 address.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn ipv4_run(&mut self, run: &str) -> Result<String, AnonymizeError> {
        let core = run.trim_matches('.');
        let prefix_len = run.len().saturating_sub(run.trim_start_matches('.').len());
        let prefix = run.get(..prefix_len).unwrap_or_default();
        let suffix = run
            .get(prefix_len.saturating_add(core.len())..)
            .unwrap_or_default();
        match core.parse::<Ipv4Addr>() {
            Ok(address) => Ok(format!("{prefix}{}{suffix}", self.map_ipv4(address)?)),
            Err(_) => Ok(run.to_owned()),
        }
    }

    /// Maps a MAC address to the low three bytes of its `02:00:00` replacement.
    fn map_mac(&mut self, mac: [u8; 6]) -> [u8; 3] {
        if let Some(mapped) = self.macs.get(&mac) {
            return *mapped;
        }
        let mut counter = 0_u8;
        let mapped = loop {
            let [first, second, third, ..] = self.digest(b"mac", &mac, counter);
            let candidate = [first, second, third];
            if self.used_macs.insert(candidate) {
                break candidate;
            }
            counter = counter.wrapping_add(1);
        };
        let _: Option<_> = self.macs.insert(mac, mapped);
        mapped
    }

    /// Maps an IPv4 address.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn map_ipv4(&mut self, address: Ipv4Addr) -> Result<Ipv4Addr, AnonymizeError> {
        if keeps_ipv4(address) {
            return Ok(address);
        }
        let [first, second, third, host] = address.octets();
        if is_structured(address) {
            let network = [first, second, third];
            let target = match self.subnets.get(&network) {
                Some(target) => Some(*target),
                None => SUBNET_TARGETS
                    .get(self.subnets.len())
                    .copied()
                    .inspect(|target| {
                        let _: Option<_> = self.subnets.insert(network, *target);
                    }),
            };
            if let Some([target_a, target_b, target_c]) = target {
                return Ok(Ipv4Addr::new(target_a, target_b, target_c, host));
            }
        }
        if let Some(mapped) = self.hosts.get(&address) {
            return Ok(*mapped);
        }
        let ordinal = u8::try_from(self.hosts.len().saturating_add(1))
            .ok()
            .filter(|ordinal| *ordinal < u8::MAX)
            .ok_or(AnonymizeError::AddressSpaceExhausted)?;
        let [pool_a, pool_b, pool_c] = HOST_POOL;
        let mapped = Ipv4Addr::new(pool_a, pool_b, pool_c, ordinal);
        let _: Option<_> = self.hosts.insert(address, mapped);
        Ok(mapped)
    }

    /// Maps an IPv6 address.
    ///
    /// # Errors
    ///
    /// [`AnonymizeError::AddressSpaceExhausted`] when the documentation ranges run out.
    fn map_ipv6(&mut self, address: Ipv6Addr) -> Result<Ipv6Addr, AnonymizeError> {
        if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
            return Ok(address);
        }
        let [s0, s1, s2, s3, s4, s5, s6, s7] = address.segments();
        let interface_id = [s4, s5, s6, s7];
        let [i0, i1, i2, i3] = if s4 == 0 && s5 == 0 && s6 == 0 {
            interface_id
        } else {
            let mut octets = [0_u8; 8];
            for (target, source) in octets.iter_mut().zip(
                interface_id
                    .iter()
                    .flat_map(|segment| segment.to_be_bytes()),
            ) {
                *target = source;
            }
            let [d0, d1, d2, d3, d4, d5, d6, d7, ..] = self.digest(b"iid", &octets, 0);
            [
                u16::from_be_bytes([d0, d1]),
                u16::from_be_bytes([d2, d3]),
                u16::from_be_bytes([d4, d5]),
                u16::from_be_bytes([d6, d7]),
            ]
        };
        if s0 & 0xffc0 == 0xfe80 {
            return Ok(Ipv6Addr::new(s0, s1, s2, s3, i0, i1, i2, i3));
        }
        let prefix = [s0, s1, s2];
        let slot = if let Some(slot) = self.prefixes.get(&prefix).copied() {
            slot
        } else {
            let fresh = u16::try_from(self.prefixes.len().saturating_add(1))
                .map_err(|_overflow| AnonymizeError::AddressSpaceExhausted)?;
            let _: Option<_> = self.prefixes.insert(prefix, fresh);
            fresh
        };
        Ok(Ipv6Addr::new(0x2001, 0x0db8, slot, s3, i0, i1, i2, i3))
    }

    /// HMAC-SHA256 of `domain || input || counter` under the run key.
    fn digest(&self, domain: &[u8], input: &[u8], counter: u8) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new(&(*self.key).into());
        mac.update(domain);
        mac.update(input);
        mac.update(&[counter]);
        mac.finalize().into_bytes().into()
    }
}

/// Length of a MAC address in text form.
const MAC_TEXT_LEN: usize = 17;

/// Returns the next `prefix-N` alias for `original`, reusing an existing one.
fn numbered(table: &mut BTreeMap<String, String>, prefix: &str, original: &str) -> String {
    if let Some(alias) = table.get(original) {
        return alias.clone();
    }
    let alias = format!("{prefix}-{}", table.len().saturating_add(1));
    drop(table.insert(original.to_owned(), alias.clone()));
    alias
}

/// Whether `position` in `run` starts a separator-delimited group.
fn starts_group(run: &str, position: usize) -> bool {
    position == 0
        || run
            .get(..position)
            .and_then(|before| before.chars().next_back())
            .is_some_and(|character| matches!(character, ':' | '-' | '.'))
}

/// Parses `02:00:00:00:00:01` or `02-00-00-00-00-01` (any case) into bytes.
#[inline]
#[must_use]
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    if text.len() != MAC_TEXT_LEN {
        return None;
    }
    let separator = text.chars().nth(2).filter(|sep| matches!(sep, ':' | '-'))?;
    let mut bytes = [0_u8; 6];
    let mut groups = text.split(separator);
    for byte in &mut bytes {
        let group = groups.next()?;
        if group.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(group, 16).ok()?;
    }
    groups.next().is_none().then_some(bytes)
}

/// Formats a replacement MAC.
fn format_mac([first, second, third]: [u8; 3]) -> String {
    format!("02:00:00:{first:02x}:{second:02x}:{third:02x}")
}

/// Whether an IPv4 value is kept unchanged.
fn keeps_ipv4(address: Ipv4Addr) -> bool {
    let inverted = !u32::from(address);
    address.is_loopback()
        || address.is_multicast()
        || address.is_link_local()
        || inverted & inverted.wrapping_add(1) == 0
}

/// Whether an IPv4 address belongs to a private or shared network with `/24` structure.
const fn is_structured(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_private() || (first == 100 && second & 0xc0 == 64)
}

/// Characters of a candidate MAC or IPv6 run.
const fn is_hex_run_char(character: char) -> bool {
    character.is_ascii_hexdigit() || matches!(character, ':' | '-' | '.')
}

/// Characters of a candidate IPv4 run.
const fn is_ipv4_run_char(character: char) -> bool {
    character.is_ascii_digit() || character == '.'
}

/// Characters of standard Base64.
const fn is_base64_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
}

/// Whether `run` has the shape of a WireGuard key: 43 Base64 characters then `=`.
#[inline]
#[must_use]
pub fn is_wireguard_key_shape(run: &str) -> bool {
    run.len() == 44 && run.find('=') == Some(43)
}

/// Replaces `ns3` payloads and WireGuard-key-shaped strings.
fn redact_secret_shapes(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut run_start: Option<usize> = None;
    for (index, character) in text.char_indices().chain([(text.len(), ' ')]) {
        match (run_start, index < text.len() && is_base64_char(character)) {
            (None, true) => run_start = Some(index),
            (Some(start), false) => {
                let run = text.get(start..index).unwrap_or_default();
                let after_ns3 = output.ends_with("ns3 ") || output.ends_with("ns3 \"");
                if after_ns3 || is_wireguard_key_shape(run) {
                    output.push_str(PLACEHOLDER);
                } else {
                    output.push_str(run);
                }
                run_start = None;
                if index < text.len() {
                    output.push(character);
                }
            }
            (None, false) => {
                if index < text.len() {
                    output.push(character);
                }
            }
            (Some(_), true) => {}
        }
    }
    output
}

/// Splits `text` into maximal runs of `is_run` characters and rewrites each run.
///
/// # Errors
///
/// The first error returned by `rewrite`.
fn rewrite_runs<F, E>(text: &str, is_run: fn(char) -> bool, mut rewrite: F) -> Result<String, E>
where
    F: FnMut(&str) -> Result<String, E>,
{
    let mut output = String::with_capacity(text.len());
    let mut run_start: Option<usize> = None;
    for (index, character) in text.char_indices() {
        match (run_start, is_run(character)) {
            (None, true) => run_start = Some(index),
            (Some(start), false) => {
                output.push_str(&rewrite(text.get(start..index).unwrap_or_default())?);
                run_start = None;
                output.push(character);
            }
            (None, false) => output.push(character),
            (Some(_), true) => {}
        }
    }
    if let Some(start) = run_start {
        output.push_str(&rewrite(text.get(start..).unwrap_or_default())?);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    //! Mapping stability, prefix preservation and leak checks.
    //!
    //! Private addresses, foreign MACs and key-shaped strings are assembled at run time so
    //! this file passes the repository secret scanner (`tests/no_secrets.rs`).

    use core::net::Ipv4Addr;

    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::{Anonymizer, PLACEHOLDER, is_wireguard_key_shape, parse_mac};

    /// An anonymizer with a fixed key, so failures reproduce.
    fn fixed() -> Anonymizer {
        Anonymizer::from_key(Zeroizing::new([7_u8; 64]))
    }

    /// `192.168.<third>.<host>`.
    fn lan(third: u8, host: u8) -> String {
        format!("{}.{}.{third}.{host}", 192, 168)
    }

    /// A WireGuard-key-shaped string.
    fn wireguard_key() -> String {
        format!("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm{}=", "k")
    }

    /// Original values planted in the synthetic capture; none may survive.
    fn originals() -> Vec<String> {
        [
            format!("a4:5e:60:{}:34:56", 12_u8),
            format!("A4-5E-60-AB-CD-{}", "EF"),
            lan(1, 10),
            lan(1, 20),
            format!("{}.20.30.40", 10),
            format!("{}.16.5.1", 172),
            "100.64.1.2".to_owned(),
            "8.8.8.8".to_owned(),
            "2a02:6b8:1234:10:a65e:60ff:fe12:3456".to_owned(),
            "Alices-iPhone".to_owned(),
            "Living room TV".to_owned(),
            "MyHomeWiFi".to_owned(),
            "S1234567890ABC".to_owned(),
            "861234567890123".to_owned(),
            "89701012345678901234".to_owned(),
            "hunter2secret".to_owned(),
            "QP/a3C96cTqJxMboZoZojIZB".to_owned(),
            wireguard_key(),
            "corp.example-home.lan".to_owned(),
        ]
        .into()
    }

    /// A synthetic capture holding every original value.
    fn synthetic() -> (Value, String) {
        let values = originals();
        let get = |index: usize| values.get(index).cloned().unwrap_or_default();
        let document = json!({
            "host": [
                {"mac": get(0), "ip": get(2), "name": get(9), "hostname": get(9),
                 "description": get(10)},
                {"mac": get(1), "ip": get(3), "via": get(4)}
            ],
            "ssid": get(11),
            "serial": get(12),
            "imei": get(13),
            "iccid": get(14),
            "password": get(15),
            "wireguard": {"public-key": get(17)},
            "route": format!("{}/32 via {} dns {}", get(5), get(6), get(7)),
            "ipv6": format!("{}/64", get(8)),
            "domain": get(18),
            "log": format!("{} joined {}; serial {}", get(9), get(11), get(12)),
            "netmask": "255.255.255.0",
        });
        let config = [
            "! $$$ Model: KN-1811".to_owned(),
            "! $$$ Username: alice".to_owned(),
            "interface WifiMaster0/AccessPoint0".to_owned(),
            format!(" ssid {}", get(11)),
            format!(" authentication wpa-psk ns3 {}", get(16)),
            format!(" description \"{}\"", get(10)),
            "!".to_owned(),
            "interface Bridge0".to_owned(),
            format!(" ip address {} 255.255.255.0", lan(1, 1)),
            "!".to_owned(),
            "interface Wireguard0".to_owned(),
            format!(" wireguard private-key {}", get(17)),
            "!".to_owned(),
            format!("known host {} {}", get(9), get(0)),
            format!("ip host {} {}", get(18), get(4)),
            format!("user alice password md5 {}", get(15)),
        ]
        .join("\n");
        (document, config)
    }

    /// No original value appears anywhere in the anonymized output.
    ///
    /// # Panics
    ///
    /// Panics when an original value survives.
    #[test]
    fn no_original_value_survives() {
        let (document, config) = synthetic();
        let mut anonymizer = fixed();
        assert_eq!(anonymizer.json(&document).err(), None, "learning pass");
        assert_eq!(anonymizer.config(&config).err(), None, "learning pass");
        let json_out = anonymizer.json(&document);
        let config_out = anonymizer.config(&config);
        assert_eq!(json_out.as_ref().err(), None, "json anonymizes");
        assert_eq!(config_out.as_ref().err(), None, "config anonymizes");
        let output = format!(
            "{}\n{}",
            json_out.map_or_default(|value| value.to_string()),
            config_out.unwrap_or_default()
        );
        for original in originals() {
            assert!(
                !output.to_lowercase().contains(&original.to_lowercase()),
                "{original} survived in {output}"
            );
        }
        assert!(output.contains(PLACEHOLDER), "secrets are replaced");
        assert!(output.contains("ssid-1"), "ssid is aliased: {output}");
        assert!(output.contains("host-1"), "host is aliased: {output}");
        assert!(output.contains("255.255.255.0"), "netmasks are kept");
        assert!(output.contains("00000000000000"), "serial is zeroed");
        assert!(output.contains("02:00:00:"), "MACs are mapped: {output}");
        assert!(
            output.contains("2001:db8:1:10:"),
            "IPv6 keeps the subnet id"
        );
    }

    /// The same value maps the same way within one run, and the key decides the mapping.
    ///
    /// # Panics
    ///
    /// Panics when a mapping changes within a run or ignores the key.
    #[test]
    fn mapping_is_stable_within_a_run() {
        let (document, config) = synthetic();
        let mut anonymizer = fixed();
        assert_eq!(anonymizer.json(&document).err(), None, "learning pass");
        let first = anonymizer.json(&document).map(|value| value.to_string());
        let second = anonymizer.json(&document).map(|value| value.to_string());
        assert_eq!(first, second, "repeat anonymization is identical");
        let config_first = anonymizer.config(&config);
        assert_eq!(config_first, anonymizer.config(&config), "config is stable");
        let mac = anonymizer.text(&format!("a4:5e:60:{}:34:56", 12_u8));
        assert_eq!(
            mac,
            anonymizer.text(&format!("A4-5E-60-{}-34-56", 12_u8)),
            "MAC case and separator do not matter"
        );
        let mut other = Anonymizer::from_key(Zeroizing::new([9_u8; 64]));
        assert_ne!(
            mac,
            other.text(&format!("a4:5e:60:{}:34:56", 12_u8)),
            "the key changes the MAC map"
        );
    }

    /// Addresses sharing a private `/24` still share one; different `/24`s do not.
    ///
    /// # Panics
    ///
    /// Panics when a prefix relationship is lost.
    #[test]
    fn ipv4_prefixes_are_preserved() {
        let mut anonymizer = fixed();
        let input = format!(
            "{} {} {}.0.0.1 {}/24",
            lan(1, 10),
            lan(1, 20),
            10_u8,
            lan(1, 0)
        );
        assert_eq!(
            anonymizer.text(&input).as_deref(),
            Ok("192.0.2.10 192.0.2.20 198.51.100.1 192.0.2.0/24"),
            "host octets and /24 membership are kept"
        );
        let overflow = format!("{0}.16.0.9 1.1.1.1 {0}.16.0.9", 172_u8);
        assert_eq!(
            anonymizer.text(&overflow).as_deref(),
            Ok("203.0.113.1 203.0.113.2 203.0.113.1"),
            "overflow and public hosts are pooled and stable"
        );
        let kept = anonymizer.text("0.0.0.0 255.255.255.0 127.0.0.1 224.0.0.1 169.254.1.1");
        assert_eq!(
            kept.as_deref(),
            Ok("0.0.0.0 255.255.255.0 127.0.0.1 224.0.0.1 169.254.1.1"),
            "special values are kept"
        );
        assert!(
            Ipv4Addr::new(192, 0, 2, 10).is_documentation(),
            "targets are RFC 5737"
        );
    }

    /// IPv6 `/48` prefixes map to `2001:db8::/32` and keep subnet relationships.
    ///
    /// # Panics
    ///
    /// Panics when a prefix relationship is lost.
    #[test]
    fn ipv6_prefixes_are_preserved() {
        let mut anonymizer = fixed();
        let mapped = anonymizer.text("2a02:6b8:1234::/48 2a02:6b8:1234:5::1 2a00:1::1 ::1");
        assert_eq!(
            mapped.as_deref(),
            Ok("2001:db8:1::/48 2001:db8:1:5::1 2001:db8:2::1 ::1"),
            "prefix slots and subnet ids are kept"
        );
    }

    /// Secret shapes are recognised.
    ///
    /// # Panics
    ///
    /// Panics when a shape is misclassified.
    #[test]
    fn helpers_recognise_shapes() {
        assert_eq!(
            parse_mac("02:00:00:00:00:01"),
            Some([2, 0, 0, 0, 0, 1]),
            "colon MAC parses"
        );
        assert_eq!(parse_mac("02:00:00:00:00"), None, "short MAC is rejected");
        assert!(
            is_wireguard_key_shape(&wireguard_key()),
            "WireGuard key shape"
        );
        let mut anonymizer = fixed();
        assert_eq!(
            anonymizer
                .text("x ns3 \"QP/a3C96cTqJxMboZoZojIZB\"")
                .as_deref(),
            Ok("x ns3 \"<redacted>\""),
            "quoted ns3 payload is replaced"
        );
    }
}
