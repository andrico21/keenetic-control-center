//! Whole captures through [`render`] and the self-check: a learned value spanning several
//! configuration words, and an interface reference in a hotspot row.
//!
//! Assertion messages never carry a planted value.

use core::error::Error;

use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::self_check;
use crate::capture::{Captured, Item, Raw, RawBody, Rendered, Request, render};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Writes `rendered` below a fresh directory and self-checks it.
///
/// # Errors
///
/// Setup I/O errors, or the self-check's refusal.
fn checked(rendered: &Rendered) -> TestResult {
    let scratch = TempDir::new()?;
    let directory = rendered.write(scratch.path())?;
    self_check(&directory, rendered)?;
    Ok(())
}

/// A route comment of two words learned from the rci root leaves no trace in the running
/// configuration, and the capture passes the self-check (todo 12).
///
/// # Errors
///
/// Setup I/O errors, or the self-check's refusal.
///
/// # Panics
///
/// Panics when the comment survives.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_route_comment_from_the_root_is_replaced_in_the_running_config() -> TestResult {
    let config = "! $$$ Model: KN-1811\n\
                  ip route 0.0.0.0 0.0.0.0 GigabitEthernet0 auto !Planted Route Note\n";
    let captured: Vec<Captured> = vec![
        (
            Item::new("rci-root", Request::Root),
            Ok(RawBody(Raw::Json(json!({"ip": {"route": [
                {"network": "0.0.0.0", "comment": "Planted Route Note"}
            ]}})))),
        ),
        (
            Item::new("running-config", Request::RunningConfig),
            Ok(RawBody(Raw::Config(Zeroizing::new(config.to_owned())))),
        ),
    ];
    let rendered = render(&captured, "KN-1811", "5.1.10");
    let text = rendered
        .files
        .get("running-config.txt")
        .ok_or("no running config")?;
    assert!(
        !text.to_lowercase().contains("planted route note"),
        "the comment survived"
    );
    checked(&rendered)
}

/// An interface reference in a hotspot row keeps its firmware id in the data and in the
/// manifest, and the capture passes the self-check (todo 12).
///
/// # Errors
///
/// Setup I/O errors, or the self-check's refusal.
///
/// # Panics
///
/// Panics when the id is aliased or learned.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn an_interface_reference_stays_readable_and_passes() -> TestResult {
    let captured: Vec<Captured> = vec![
        (
            Item::new("show-ip-hotspot", Request::Show("show/ip/hotspot")),
            Ok(RawBody(Raw::Json(json!({"host": [{
                "name": "Planted7",
                "interface": {"id": "Bridge0", "name": "Bridge0", "description": "Planted Segment"},
            }]})))),
        ),
        (
            Item::new(
                "show-interface-stat-Bridge0",
                Request::InterfaceStat("Bridge0".to_owned()),
            ),
            Ok(RawBody(Raw::Json(json!({"rxbytes": 1_u8})))),
        ),
    ];
    let rendered = render(&captured, "KN-1811", "5.1.10");
    let hotspot = rendered
        .files
        .get("show-ip-hotspot.json")
        .ok_or("no hotspot file")?;
    assert!(hotspot.contains("\"Bridge0\""), "the interface id is kept");
    assert!(
        !rendered
            .identifiers
            .iter()
            .any(|identifier| identifier.value == "Bridge0"),
        "the interface id is not learned"
    );
    assert!(
        rendered
            .identifiers
            .iter()
            .any(|identifier| identifier.value == "Planted7"),
        "the host name is learned"
    );
    checked(&rendered)
}
