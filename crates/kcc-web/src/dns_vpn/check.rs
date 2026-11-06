//! Values typed into the DNS and VPN forms, checked before anything is planned.
//!
//! The DNS and VPN domains render their CLI lines by joining the values with spaces, so a
//! value that passes here is one conservative token: no space, no quote, no control
//! character. A value that fails is answered with its field's error and nothing is sent.

use core::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr as _,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use url::Url;

/// Longest name of a domain list or a filter profile, in characters.
const NAME_CHARS: usize = 32;

/// Longest domain name, in bytes.
const DOMAIN_BYTES: usize = 253;

/// Longest label of a domain name, in bytes.
const LABEL_BYTES: usize = 63;

/// Longest resolver URL, in bytes.
const URL_BYTES: usize = 256;

/// Longest interface name, in bytes (the router's object-name limit).
const INTERFACE_BYTES: usize = 64;

/// Bytes of a decoded WireGuard key.
const KEY_BYTES: usize = 32;

/// An IP address.
pub(crate) fn ip(value: &str) -> Option<String> {
    IpAddr::from_str(value.trim())
        .ok()
        .map(|address| address.to_string())
}

/// A value that is not valid for its field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

/// The value of an optional field: `None` when left empty.
pub(crate) type Optional<T> = Result<Option<T>, Invalid>;

/// The optional field `value`, empty or checked by `parse`.
///
/// # Errors
///
/// Returns [`Invalid`] when the value is not empty and `parse` refuses it.
pub(crate) fn optional<T, F>(value: &str, parse: F) -> Optional<T>
where
    F: FnOnce(&str) -> Option<T>,
{
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse(trimmed).map(Some).ok_or(Invalid)
    }
}

/// A port from 1 to 65535; empty is none.
///
/// # Errors
///
/// Returns [`Invalid`] for anything else.
pub(crate) fn port(value: &str) -> Optional<u16> {
    optional_number(value, 1)
}

/// A number of seconds or addresses from `low` to 65535; empty is none.
///
/// # Errors
///
/// Returns [`Invalid`] for anything else.
pub(crate) fn optional_number(value: &str, low: u16) -> Optional<u16> {
    optional(value, |text| {
        text.parse::<u16>().ok().filter(|number| *number >= low)
    })
}

/// A name of a domain list or a filter profile: 1 to 32 Latin letters, digits, `_` and
/// `-`, starting with a letter or a digit.
pub(crate) fn name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let valid = (1..=NAME_CHARS).contains(&trimmed.len())
        && trimmed.starts_with(|first: char| first.is_ascii_alphanumeric())
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    valid.then(|| trimmed.to_owned())
}

/// A domain name: dot-separated labels of Latin letters, digits and hyphens.
pub(crate) fn domain(value: &str) -> Option<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    let valid = (1..=DOMAIN_BYTES).contains(&trimmed.len())
        && trimmed.split('.').all(|label| {
            (1..=LABEL_BYTES).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    valid.then_some(trimmed)
}

/// An `https://` resolver URL with a host, in printable ASCII with no quotes.
pub(crate) fn https_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let printable = trimmed
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\' | b'`'));
    if trimmed.len() > URL_BYTES || !printable {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    (url.scheme() == "https" && url.host_str().is_some()).then(|| trimmed.to_owned())
}

/// A MAC address, six pairs of hex digits separated by `:` or `-`, as lowercase with `:`.
pub(crate) fn mac(value: &str) -> Option<String> {
    let trimmed = value.trim().to_ascii_lowercase().replace('-', ":");
    let pairs: Vec<&str> = trimmed.split(':').collect();
    let valid = pairs.len() == 6
        && pairs
            .iter()
            .all(|pair| pair.len() == 2 && pair.bytes().all(|byte| byte.is_ascii_hexdigit()));
    valid.then_some(trimmed)
}

/// A name the router gave an object, such as an interface (`Wireguard0`), a domain list or
/// a filter profile: one token of the router's object-name characters.
pub(crate) fn object(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let valid = (1..=INTERFACE_BYTES).contains(&trimmed.len())
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b':' | b'-')
        });
    valid.then(|| trimmed.to_owned())
}

/// The name of a WireGuard connection: `Wireguard` and its number, 0 to 999.
pub(crate) fn tunnel(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let number = trimmed.strip_prefix("Wireguard")?;
    let valid = (1..=3).contains(&number.len()) && number.bytes().all(|byte| byte.is_ascii_digit());
    valid.then(|| trimmed.to_owned())
}

/// A WireGuard public key: Base64 of 32 bytes.
pub(crate) fn wireguard_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let decoded = STANDARD.decode(trimmed).ok()?;
    (decoded.len() == KEY_BYTES).then(|| trimmed.to_owned())
}

/// An IPv4 range in CIDR form, such as `192.0.2.0/24`, as the address and its dotted mask.
pub(crate) fn ipv4_range(value: &str) -> Option<(String, String)> {
    let (address_text, bits_text) = value.trim().split_once('/')?;
    let address = Ipv4Addr::from_str(address_text).ok()?;
    let bits = bits_text.parse::<u32>().ok().filter(|count| *count <= 32)?;
    let mask = u32::MAX
        .checked_shl(32_u32.saturating_sub(bits))
        .unwrap_or(0);
    Some((address.to_string(), Ipv4Addr::from(mask).to_string()))
}

/// Every IPv4 range of a comma-separated list; an empty list is empty.
pub(crate) fn ipv4_ranges(value: &str) -> Option<Vec<(String, String)>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ipv4_range)
        .collect()
}

/// An endpoint `address:port` whose address is an IP address (`[v6]:port` for IPv6).
pub(crate) fn endpoint(value: &str) -> Option<(String, u16)> {
    let (host, port_text) = value.trim().rsplit_once(':')?;
    let address = ip(host.trim_start_matches('[').trim_end_matches(']'))?;
    let port_number = port(port_text).ok()??;
    Some((address, port_number))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{domain, endpoint, https_url, ipv4_range, mac, name, object, tunnel};

    #[test]
    fn every_value_becomes_one_safe_token_or_nothing() {
        assert_eq!(domain(" NAS.home "), Some("nas.home".to_owned()), "domain");
        for bad in ["", "a b.com", "-a.com", "a..com", "a.com;reboot", "a\"b"] {
            assert_eq!(domain(bad), None, "{bad}");
        }
        assert_eq!(name("streaming_1"), Some("streaming_1".to_owned()), "name");
        for bad in ["", "_x", "two words", "x\ny", &"x".repeat(33)] {
            assert_eq!(name(bad), None, "{bad}");
        }
        assert!(https_url("https://dns.example/dns-query").is_some(), "url");
        for bad in [
            "http://dns.example/",
            "https://",
            "https://a b/",
            "https://x/\"q",
        ] {
            assert_eq!(https_url(bad), None, "{bad}");
        }
        assert_eq!(
            mac("02-00-00-00-11-0A"),
            Some("02:00:00:00:11:0a".to_owned()),
            "mac"
        );
        assert_eq!(object("Bridge0 up"), None, "one token");
        assert_eq!(
            tunnel("Wireguard12"),
            Some("Wireguard12".to_owned()),
            "tunnel"
        );
        assert_eq!(tunnel("OpenVPN0"), None, "WireGuard only");
        assert_eq!(
            ipv4_range("192.0.2.0/24"),
            Some(("192.0.2.0".to_owned(), "255.255.255.0".to_owned())),
            "mask"
        );
        assert_eq!(
            ipv4_range("0.0.0.0/0"),
            Some(("0.0.0.0".to_owned(), "0.0.0.0".to_owned())),
            "default route"
        );
        assert_eq!(ipv4_range("::/0"), None, "IPv4 only");
        assert_eq!(
            endpoint("[2001:db8::1]:51820"),
            Some(("2001:db8::1".to_owned(), 51820)),
            "IPv6 endpoint"
        );
        assert_eq!(endpoint("vpn.example:51820"), None, "IP addresses only");
    }
}
