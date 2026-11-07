//! Unit tests of the static route parser: stored shapes, and rows that are not routes.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use kcc_domain::routing::model::RouteTableEntry;
use serde_json::{Value, json};

use super::{Family, StaticRoute, mask, prefix};

/// A routing-table row from its JSON.
fn entry(value: Value) -> Result<RouteTableEntry, Box<dyn Error>> {
    Ok(serde_json::from_value(value)?)
}

#[test]
fn stored_static_shapes_parse_back_to_the_same_command() -> Result<(), Box<dyn Error>> {
    for (family, words, stored) in [
        (
            Family::V4,
            json!(["198.51.100.0", "255.255.255.0", "192.0.2.254", "ISP", "7"]),
            "ip route 198.51.100.0 255.255.255.0 192.0.2.254 ISP 7",
        ),
        (
            Family::V4,
            json!(["203.0.113.0", "255.255.255.0", "Wireguard0"]),
            "ip route 203.0.113.0 255.255.255.0 Wireguard0",
        ),
        (
            Family::V4,
            json!(["192.0.2.5", "255.255.255.255", "192.0.2.254", "3"]),
            "ip route 192.0.2.5 255.255.255.255 192.0.2.254 3",
        ),
        (
            Family::V6,
            json!(["2001:db8:7::/64", "2001:db8::1", "ISP"]),
            "ipv6 route 2001:db8:7::/64 2001:db8::1 ISP",
        ),
    ] {
        let row = entry(json!({"static": true, "command": words}))?;
        let route = StaticRoute::from_entry(family, &row).ok_or("a static route")?;
        assert_eq!(route.stored(), stored, "stored form");
        assert!(route.well_formed(), "{stored} is well formed");
    }
    Ok(())
}

#[test]
fn runtime_rows_and_unknown_shapes_are_not_static_routes() -> Result<(), Box<dyn Error>> {
    let runtime = entry(json!({"destination": "0.0.0.0/0", "gateway": "203.0.113.1"}))?;
    assert_eq!(
        StaticRoute::from_entry(Family::V4, &runtime),
        None,
        "runtime"
    );
    let short = entry(json!({"static": true, "command": ["198.51.100.0"]}))?;
    assert_eq!(
        StaticRoute::from_entry(Family::V4, &short),
        None,
        "too short"
    );
    let extra = entry(json!({"static": true, "command": ["2001:db8::/64", "ISP", "9"]}))?;
    assert_eq!(
        StaticRoute::from_entry(Family::V6, &extra),
        None,
        "no IPv6 metric"
    );
    Ok(())
}

#[test]
fn masks_and_prefixes_must_be_well_formed() {
    assert!(mask("255.255.255.0"), "contiguous");
    assert!(mask("0.0.0.0"), "default");
    assert!(!mask("255.0.255.0"), "holes");
    assert!(!mask("24"), "a prefix length is not a dotted mask");
    assert!(prefix("2001:db8:7::/64"), "prefix");
    assert!(!prefix("2001:db8:7::"), "no length");
    assert!(!prefix("2001:db8:7::/129"), "too long");
}
