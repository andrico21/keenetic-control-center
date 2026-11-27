//! Case variants, words glued to a learned value, non-ASCII names, the `show schedule`
//! array answer and other MAC spellings.
//!
//! Foreign MACs are assembled at run time so this file passes the repository secret scanner
//! (`tests/no_secrets.rs`). Assertion messages never carry a planted value.

use core::net::Ipv6Addr;

use serde_json::json;
use zeroize::Zeroizing;

use super::{Anonymizer, IdentifierKind};
use crate::anonymize::fold::fold;

/// An anonymizer with a fixed key, so failures reproduce.
fn fixed() -> Anonymizer {
    Anonymizer::from_key(Zeroizing::new([7_u8; 64]))
}

/// Case variants and values glued to word characters are rewritten (todo 4).
///
/// A learned name or SSID of six or more characters is replaced in any case and inside a
/// longer word; no case variant of it survives in free text.
///
/// # Panics
///
/// Panics when a variant survives.
#[test]
fn learned_names_are_replaced_in_any_case_and_inside_words() {
    let mut anonymizer = fixed();
    let learned = anonymizer.json(&json!([{"name": "PLANTED-HOST-7", "ssid": "PlantedSsid"}]));
    assert!(learned.is_ok(), "learning pass");
    let line = "note: planted-host-7_laptop end; xplanted-host-7 Planted-Host-7-pc \
                PLANTED-HOST-7 plantedssid5g PLANTEDSSID";
    let output = anonymizer.text(line).unwrap_or_default();
    for (index, needle) in ["planted-host-7", "plantedssid"].into_iter().enumerate() {
        assert!(
            !fold(&output).contains(needle),
            "variant {index} survived the anonymizer"
        );
    }
    assert!(
        output.starts_with("note: host-1_laptop end;"),
        "the rest is kept"
    );
    assert!(output.contains("ssid-1"), "the SSID is aliased");
}

/// A name written in another script is learned and rewritten in any case (todo 4).
///
/// # Panics
///
/// Panics when the name is not an identifier or an uppercase variant survives.
#[test]
fn non_ascii_names_are_learned_and_rewritten() {
    let mut anonymizer = fixed();
    let name = "\u{414}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439}";
    let aliased = anonymizer.json(&json!({"name": name}));
    assert_eq!(aliased.ok(), Some(json!({"name": "host-1"})), "aliased");
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .any(|found| found.value == name && found.kind == IdentifierKind::Host),
        "the non-ASCII name is an identifier"
    );
    let output = anonymizer.text("\u{414}\u{41e}\u{41c}\u{410}\u{428}\u{41d}\u{418}\u{419}-\u{41f}\u{41a} \u{43f}\u{43e}\u{434}\u{43a}\u{43b}\u{44e}\u{447}\u{451}\u{43d}").unwrap_or_default();
    assert!(
        !fold(&output).contains(&fold(name)),
        "uppercase variant survived"
    );
    let shaped = anonymizer.json(&json!({"serial": "0000-00", "description": "----"}));
    assert!(shaped.is_ok(), "zero-shaped values anonymize");
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .all(|found| found.value != "0000-00" && found.value != "----"),
        "zeroed and punctuation-only values identify nothing"
    );
}

/// A `show schedule` answer holding an array under `schedule` keeps that word (todo 4).
///
/// The rows' `name` is aliased; the word `schedule` itself is not learned, so it stays in
/// every other text.
///
/// # Panics
///
/// Panics when `schedule` is aliased or learned.
#[test]
fn schedule_array_answer_keeps_the_word_schedule() {
    let mut anonymizer = fixed();
    let answer = json!({"schedule": [{"name": "PLANTEDS", "action": []}]});
    let output = anonymizer.schedules(&answer);
    assert_eq!(
        output.ok(),
        Some(json!({"schedule": [{"name": "host-1", "action": []}]})),
        "only the row name is aliased"
    );
    assert_eq!(
        anonymizer.text("interface schedule night").as_deref(),
        Ok("interface schedule night"),
        "the word schedule is kept"
    );
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .all(|found| found.value != "schedule"),
        "the word schedule is not an identifier"
    );
}

/// A learned MAC is rewritten in its dotted and bare spellings too (todo 4).
///
/// # Panics
///
/// Panics when a spelling of the MAC survives.
#[test]
fn learned_macs_are_rewritten_in_dotted_and_bare_form() {
    let mut anonymizer = fixed();
    let colon = format!("a4:b1:c2:{}:e4:f5", "d3");
    assert!(anonymizer.text(&colon).is_ok(), "learning pass");
    let dotted = format!("A4B1.C2D3.{}", "E4F5");
    let bare = format!("a4b1c2d3{}", "e4f5");
    let output = anonymizer
        .text(&format!("arp {dotted} lease {bare}."))
        .unwrap_or_default();
    let folded = fold(&output);
    assert!(!folded.contains(&fold(&dotted)), "dotted MAC survived");
    assert!(!folded.contains(&bare), "bare MAC survived");
    assert!(folded.starts_with("arp 0200.00"), "dotted form is kept");
    assert!(folded.contains(" lease 020000"), "bare form is kept");
    assert!(folded.ends_with('.'), "trailing punctuation is kept");
}

/// A link-local address that keeps its interface id maps to itself and is not learned; one
/// with a hashed interface id is rewritten and learned (todo 4).
///
/// # Panics
///
/// Panics when an unchanged link-local is learned or a hashed one is not.
#[test]
fn link_local_addresses_are_learned_only_when_rewritten() {
    let mut anonymizer = fixed();
    let kept = "route fe80::/64 dev br0 via fe80::1";
    assert_eq!(anonymizer.text(kept).as_deref(), Ok(kept), "kept unchanged");
    assert!(
        anonymizer.identifiers().is_empty(),
        "an unchanged link-local is not learned"
    );
    let hashed = "fe80::1a2b:3c4d:5e6f:7a8b";
    let output = anonymizer
        .text(&format!("peer {hashed}"))
        .unwrap_or_default();
    assert!(!output.contains(hashed), "the interface id is rewritten");
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .any(|found| found.value == hashed && found.kind == IdentifierKind::Address),
        "a rewritten link-local is learned"
    );
}

/// A scope operator between words is not an IPv6 address; a bracketed one still is (todo 4).
///
/// # Panics
///
/// Panics when a log word is rewritten or learned, or a bracketed address survives.
#[test]
fn scope_operators_are_not_read_as_ipv6() {
    let mut anonymizer = fixed();
    let line = "Core::Authenticator: ok; Network::Interface::Ethernet up";
    assert_eq!(anonymizer.text(line).as_deref(), Ok(line), "log words kept");
    assert!(anonymizer.identifiers().is_empty(), "nothing is learned");
    let address = anonymizer.text("[2a02:6b8::1]:80").unwrap_or_default();
    assert_eq!(
        address, "[2001:db8:1::1]:80",
        "a bracketed address is mapped"
    );
}

/// A global address with a public prefix, built at run time so no address literal is in
/// the tree; `last` is its final group.
fn global(last: u16) -> String {
    Ipv6Addr::new(0x2a02, 0x06b8, 0x1c2d, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f, last).to_string()
}

/// A glued run of three or more groups is an address, rewritten and learned; a glued scope
/// operator of two groups or fewer is kept and not learned (todo 4).
///
/// # Panics
///
/// Panics when a glued address survives or a scope operator is rewritten or learned.
#[test]
fn glued_runs_of_three_groups_are_addresses() {
    let mut anonymizer = fixed();
    let address = global(0x7a8b);
    for (case, line) in [
        ("letter after", format!("{address}via")),
        ("Cyrillic before", format!("\u{448}{address}")),
    ] {
        let output = anonymizer.text(&line).unwrap_or_default();
        assert!(!output.contains(&address), "{case}: the address survived");
        assert!(output.contains("2001:db8:"), "{case}: it is mapped");
    }
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .any(|found| found.value == address && found.kind == IdentifierKind::Address),
        "the glued address is learned"
    );
    let mut fresh = fixed();
    for kept in [
        "Core::Authenticator: ok",
        "NDM::Something::x",
        "Network::Interface::Ipv6::Address",
        "xe::Ay",
    ] {
        assert_eq!(
            fresh.text(kept).as_deref(),
            Ok(kept),
            "a scope operator kept"
        );
    }
    assert!(fresh.identifiers().is_empty(), "nothing is learned");
}

/// An address after `addr:`, after hex letters (`via`) and both ends of a range are
/// rewritten; the text around them is kept (todo 4).
///
/// # Panics
///
/// Panics when an address survives or the surrounding text changes.
#[test]
fn prefixed_addresses_and_ranges_are_rewritten() {
    let mut anonymizer = fixed();
    let first = global(1);
    let second = global(0xff);
    let output = anonymizer
        .text(&format!("addr:{first} via{first} pool {first}-{second}."))
        .unwrap_or_default();
    for (index, address) in [&first, &second].into_iter().enumerate() {
        assert!(
            !output.contains(address.as_str()),
            "address {index} survived"
        );
    }
    assert!(
        output.starts_with("addr:2001:db8:"),
        "the colon prefix is kept"
    );
    assert!(
        output.contains(" via2001:db8:"),
        "the letter prefix is kept"
    );
    assert!(output.ends_with('.'), "the trailing dot is kept");
    assert_eq!(
        output.matches("2001:db8:").count(),
        4,
        "every address is mapped"
    );
}
