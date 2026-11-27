//! Address spellings the anonymizer rewrites beyond the plain forms.
//!
//! A global address joined to a link-local or multicast group, a multicast group embedding
//! a prefix, a solicited-node group, and an IPv4 address dashed, underscored, zero-padded
//! or followed by a dotted port.
//!
//! Addresses are built at run time so no address literal is in the tree. Assertion
//! messages never carry a planted value.

use core::net::{Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

use super::{Anonymizer, IdentifierKind};

/// An anonymizer with a fixed key, so failures reproduce.
fn fixed() -> Anonymizer {
    Anonymizer::from_key(Zeroizing::new([7_u8; 64]))
}

/// A global address with a public prefix, its compressed form, the text of its `/48` and
/// the `/48`'s last group (the site).
fn global() -> (String, String, String, String) {
    let full = Ipv6Addr::new(
        0x2a02, 0x06b8, 0x1c2d, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f, 0x7a8b,
    );
    let compressed = Ipv6Addr::new(0x2a02, 0x06b8, 0x1c2d, 0, 0, 0x3c4d, 0x5e6f, 0x7a8b);
    let [first, second, third, ..] = full.segments();
    (
        full.to_string(),
        compressed.to_string(),
        format!("{first:x}:{second:x}:{third:x}"),
        format!("{third:x}"),
    )
}

/// A public IPv4 address and its octets.
fn public_ipv4() -> (Ipv4Addr, [u8; 4]) {
    let octets = [81, 2, 69, 160];
    (Ipv4Addr::from(octets), octets)
}

/// The octets of `address` joined by `separator`.
fn spelled(octets: [u8; 4], separator: &str) -> String {
    octets.map(|octet| octet.to_string()).join(separator)
}

/// A global address joined by a colon after a link-local or multicast group, or embedded
/// in an RFC 3306 multicast group, never survives: no group of its `/48` is left (todo 4).
///
/// # Panics
///
/// Panics when a group of the prefix survives or the form is not learned.
#[test]
fn addresses_joined_to_link_local_or_multicast_groups_are_rewritten() {
    let (full, compressed, prefix, third) = global();
    for (case, line) in [
        ("link-local, full", format!("fe80:{full}")),
        ("link-local, compressed", format!("fe80:{compressed}")),
        ("multicast, full", format!("ff02:{full}")),
        ("multicast, compressed", format!("ff02:{compressed}")),
        ("RFC 3306 group", format!("join ff3e:40:{prefix}:1::1 ok")),
    ] {
        let mut anonymizer = fixed();
        let output = anonymizer.text(&line).unwrap_or_default();
        assert!(!output.contains(&prefix), "{case}: the /48 survived");
        assert!(
            !output.contains(&format!(":{third}")),
            "{case}: the site group survived"
        );
        assert!(output.contains("2001:db8:"), "{case}: it is mapped");
        assert!(
            anonymizer
                .identifiers()
                .iter()
                .any(|found| found.kind == IdentifierKind::Address),
            "{case}: the form is learned"
        );
    }
}

/// A solicited-node group keeps its shape; its low 24 bits, taken from an interface id,
/// are rewritten unless they fit in 16 bits (todo 4).
///
/// # Panics
///
/// Panics when a long group survives or a short one changes.
#[test]
fn solicited_node_groups_hide_long_interface_bits() {
    let mut anonymizer = fixed();
    let long = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff3c, 0x4d5e).to_string();
    let output = anonymizer.text(&format!("join {long}")).unwrap_or_default();
    assert!(!output.contains(&long), "the low bits survived");
    assert!(output.starts_with("join ff02::1:ff"), "the shape is kept");
    let short = "join ff02::1:ff00:1 ff02::2 ff05::1:3";
    assert_eq!(
        anonymizer.text(short).as_deref(),
        Ok(short),
        "short groups kept"
    );
}

/// A public IPv4 address dashed or underscored in a host name label, zero-padded, or
/// followed by a port is rewritten like its dotted form (todo 4).
///
/// # Panics
///
/// Panics when a spelling survives or maps differently from the dotted form.
#[test]
fn ipv4_spellings_are_rewritten_like_the_dotted_form() {
    let mut anonymizer = fixed();
    let (address, octets) = public_ipv4();
    let mapped = anonymizer.text(&address.to_string()).unwrap_or_default();
    let target: [u8; 4] = mapped
        .parse::<Ipv4Addr>()
        .map_or_default(|found| found.octets());
    let padded = octets.map(|octet| format!("{octet:03}")).join(".");
    for (case, line, expected) in [
        (
            "dashed, label end",
            format!("host-{}.isp.example", spelled(octets, "-")),
            format!("host-{}.isp.example", spelled(target, "-")),
        ),
        (
            "dashed, label start",
            format!("{}-gw.static.example", spelled(octets, "-")),
            format!("{}-gw.static.example", spelled(target, "-")),
        ),
        (
            "underscored",
            format!("ip_{}", spelled(octets, "_")),
            format!("ip_{}", spelled(target, "_")),
        ),
        (
            "zero-padded",
            format!("peer {padded}"),
            format!("peer {mapped}"),
        ),
        (
            "dotted port",
            format!("{address}.443"),
            format!("{mapped}.443"),
        ),
        (
            "colon port",
            format!("{address}:8080"),
            format!("{mapped}:8080"),
        ),
    ] {
        let output = anonymizer.text(&line).unwrap_or_default();
        assert!(
            output == expected,
            "{case}: not rewritten like the dotted form"
        );
    }
    for kept in ["firmware 5.1.10", "oid 1.3.6.1.2.1.1", "on 2026-11-27"] {
        assert_eq!(
            anonymizer.text(kept).as_deref(),
            Ok(kept),
            "a version is kept"
        );
    }
}
