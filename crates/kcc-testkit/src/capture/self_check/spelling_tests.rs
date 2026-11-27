//! The self-check finds a learned address in other spellings; realistic text passes.
//!
//! The spellings: an IPv4 address dashed, underscored or zero-padded, a learned `/48`
//! inside another IPv6 address, and a global address joined to a link-local or multicast
//! group.
//!
//! Addresses are built at run time so no address literal is in the tree. Assertion
//! messages never carry a planted value.

use core::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::tests::{identifier, leak_in};
use crate::anonymize::{Anonymizer, IdentifierKind};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// A learned public IPv4 address is found dashed, underscored, zero-padded and glued;
/// non-4-chain forms (5+ numbers) and version strings pass (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when a spelling passes or a version string fails.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn learned_ipv4_addresses_are_found_in_every_spelling() -> TestResult {
    let octets = [81_u8, 2, 69, 160];
    let learned = [identifier(
        &Ipv4Addr::from(octets).to_string(),
        IdentifierKind::Address,
    )];
    let joined = |separator: &str| octets.map(|octet| octet.to_string()).join(separator);
    let padded = octets.map(|octet| format!("{octet:03}")).join(".");
    let dotted = octets.map(|octet| octet.to_string()).join(".");
    for (case, content) in [
        ("dashed", format!("host-{}.isp.example", joined("-"))),
        ("dashed and glued", format!("x{}y", joined("-"))),
        ("underscored", format!("ip_{}", joined("_"))),
        ("zero-padded", format!("peer {padded}")),
        ("with extra octet", format!("{dotted}.65536")),
        ("dyn form with dash", format!("dyn-{}-1", joined("-"))),
        ("prefix with single octet", format!("9.9.{dotted}")),
    ] {
        assert_eq!(
            leak_in(&content, &learned)?,
            Some(IdentifierKind::Address),
            "{case} spelling passed"
        );
    }
    let versions = "firmware 5.1.10 1.0.0.0 4.3.6.3 oid 1.3.6.1.2.1.1 on 2026-11-27";
    assert_eq!(
        leak_in(versions, &learned)?,
        None,
        "a version string failed"
    );
    Ok(())
}

/// A learned global address's `/48` is found inside any other IPv6 address, and a global
/// address joined to a link-local or multicast group fails unlearned (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when an embedded prefix passes.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn embedded_prefixes_and_joined_groups_fail_the_self_check() -> TestResult {
    let address = Ipv6Addr::new(
        0x2a02, 0x06b8, 0x1c2d, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f, 0x7a8b,
    );
    let [first, second, third, ..] = address.segments();
    let prefix = format!("{first:x}:{second:x}:{third:x}");
    let learned = [identifier(&address.to_string(), IdentifierKind::Address)];
    for (case, content) in [
        ("after another group", format!("x cafe:{prefix}::1 y")),
        ("RFC 3306 group", format!("join ff3e:40:{prefix}:1::1")),
    ] {
        assert_eq!(
            leak_in(&content, &learned)?,
            Some(IdentifierKind::Address),
            "{case} passed"
        );
    }
    let carried = [identifier(
        &Ipv6Addr::new(0xfe80, first, second, third, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f).to_string(),
        IdentifierKind::Address,
    )];
    assert_eq!(
        leak_in(&format!("x cafe:{prefix}::1 y"), &carried)?,
        Some(IdentifierKind::Address),
        "a prefix learned inside a link-local form passed"
    );
    for (case, content) in [
        ("link-local joined", format!("fe80:{address}")),
        ("multicast joined", format!("ff02:{address}")),
        ("RFC 3306 group", format!("ff3e:40:{prefix}:1::1")),
    ] {
        assert_eq!(
            leak_in(&content, &[])?,
            Some(IdentifierKind::Address),
            "{case} passed unlearned"
        );
    }
    Ok(())
}

/// Realistic Keenetic text anonymizes and passes the self-check; words that are no address
/// stay unchanged (todo 4).
///
/// # Errors
///
/// Anonymizer or setup I/O errors.
///
/// # Panics
///
/// Panics when a realistic text fails or a word is rewritten.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn realistic_router_text_passes_unchanged() -> TestResult {
    let unchanged = [
        "Core::Authenticator: ok",
        "Core::Configurator: done",
        "NDM::Something::x",
        "ndmp:: up",
        "GigabitEthernet0/Vlan2",
        "at 12:34:56",
        "firmware 5.1.10",
        "route fe80::/64 via fe80::1",
        "group ff02::1 lo ::1",
    ];
    let rewritten = [
        "a::b",
        "Ipv6::Prefix::Delegation 2::",
        "uptime 20::",
        "mac 02:00:00:00:07:01 02-00-00-00-07-02 0200.0000.0703",
        "release 1.0.0.0 4.3.6.3",
    ];
    for text in unchanged.into_iter().chain(rewritten) {
        let mut anonymizer = Anonymizer::new();
        let output = anonymizer.text(text)?;
        if unchanged.contains(&text) {
            assert_eq!(output, text, "a word is rewritten");
        }
        assert_eq!(
            leak_in(&output, &anonymizer.identifiers())?,
            None,
            "a realistic text failed"
        );
    }
    Ok(())
}
