//! The self-check over a rendered capture: protocol tokens and fixed item names pass, only
//! the files this run wrote are scanned, and any error removes the capture.
//!
//! Assertion messages never carry a planted value.

use core::{error::Error, net::Ipv6Addr};
use std::{fs, path::PathBuf};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::self_check;
use crate::{
    anonymize::{IdentifierKind, vocabulary::Vocabulary},
    capture::{CaptureError, Captured, Item, Raw, RawBody, Rendered, Request, render},
};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// A captured JSON answer of the item `name` read by `request`.
fn answered(name: &str, request: Request, value: Value) -> Captured {
    (Item::new(name, request), Ok(RawBody(Raw::Json(value))))
}

/// The capture of a router whose components are named like protocol words and that has
/// the `wireguard-server` item.
fn captured() -> Vec<Captured> {
    vec![
        answered(
            "components-list",
            Request::Continued("components/list", json!({}), 30),
            json!([[
                {"name": "wireguard", "installed": true},
                {"name": "sstp-server", "installed": false},
                {"name": "storage", "installed": true, "description": "Planted Storage"}
            ]]),
        ),
        answered(
            "components-preview",
            Request::Continued("components/preview", json!({}), 0),
            json!([{"component": {"wireguard": {
                "name": "wireguard", "description": "WireGuard VPN", "group": "Network"
            }}}]),
        ),
        answered(
            "show-components-status",
            Request::Show("show/components/status"),
            json!({"component": [{"name": "sstp-server", "description": "SSTP Server"}]}),
        ),
        answered(
            "show-components-pending",
            Request::Show("show/components/pending"),
            json!({"install": ["opkg"], "remove": []}),
        ),
        answered(
            "show-rc-wireguard-server",
            Request::ShowRc(&["wireguard-server"]),
            json!({}),
        ),
    ]
}

/// Renders [`captured`] and writes it below a fresh directory.
///
/// # Errors
///
/// I/O errors from writing.
fn written() -> Result<(TempDir, PathBuf, Rendered), Box<dyn Error>> {
    let scratch = TempDir::new()?;
    let rendered = render(&captured(), "KN-1811", "5.1.3");
    let directory = rendered.write(scratch.path())?;
    Ok((scratch, directory, rendered))
}

/// Component names are protocol tokens: kept, not learned, and so no leak where they are
/// part of a fixed item name of the manifest (todo 4).
///
/// # Errors
///
/// Setup I/O errors or a failing self-check.
///
/// # Panics
///
/// Panics when a component name is rewritten or learned.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn component_names_and_fixed_item_names_pass_the_self_check() -> TestResult {
    let (_scratch, directory, rendered) = written()?;
    self_check(&directory, &rendered)?;
    let components = fs::read_to_string(directory.join("components-list.json"))?;
    for name in ["\"wireguard\"", "\"sstp-server\"", "\"storage\""] {
        assert!(components.contains(name), "a component name is rewritten");
    }
    let keyed = fs::read_to_string(directory.join("components-preview.json"))?;
    for word in ["\"wireguard\": {", "\"WireGuard VPN\""] {
        assert!(keyed.contains(word), "a keyed component is rewritten");
    }
    assert!(
        components.contains("\"Planted Storage\""),
        "a component description is rewritten"
    );
    let status = fs::read_to_string(directory.join("show-components-status.json"))?;
    for word in ["\"sstp-server\"", "\"SSTP Server\""] {
        assert!(status.contains(word), "a nested component is rewritten");
    }
    let pending = fs::read_to_string(directory.join("show-components-pending.json"))?;
    assert!(
        pending.contains("\"opkg\""),
        "a pending component is rewritten"
    );
    assert!(
        !rendered.identifiers.iter().any(|identifier| matches!(
            identifier.value.as_str(),
            "wireguard" | "sstp-server" | "WireGuard VPN" | "SSTP Server" | "Planted Storage"
        )),
        "a component name is learned"
    );
    Ok(())
}

/// A client named like part of a fixed item name passes the self-check: the fixed item
/// names of the manifest are not scanned (todo 4).
///
/// # Errors
///
/// Setup I/O errors or a failing self-check.
#[test]
fn a_client_named_like_a_fixed_item_passes_the_self_check() -> TestResult {
    let scratch = TempDir::new()?;
    let captured = [
        answered(
            "show-ip-arp",
            Request::Show("show/ip/arp"),
            json!([{"name": "wireguard", "ip": "192.0.2.7"}]),
        ),
        answered(
            "show-rc-wireguard-server",
            Request::ShowRc(&["wireguard-server"]),
            json!({}),
        ),
    ];
    let rendered = render(&captured, "KN-1811", "5.1.3");
    let directory = rendered.write(scratch.path())?;
    self_check(&directory, &rendered)?;
    Ok(())
}

/// Only the files this run wrote are scanned, and an error while scanning them removes the
/// capture (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when a foreign entry fails the check or a failed check leaves the capture.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn only_written_files_are_scanned_and_an_error_removes_the_capture() -> TestResult {
    let (_scratch, directory, rendered) = written()?;
    fs::create_dir_all(directory.join("000"))?;
    fs::write(directory.join("stale.bin"), [0xff_u8, 0xfe])?;
    self_check(&directory, &rendered)?;
    fs::write(directory.join("components-list.json"), [0xff_u8, 0xfe])?;
    let failed = self_check(&directory, &rendered);
    assert!(matches!(failed, Err(CaptureError::Io(_))), "{failed:?}");
    assert!(!directory.exists(), "the capture is removed on an error");
    Ok(())
}

/// A capture directory that already exists is refused, its content kept (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when the directory is reused.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn an_existing_capture_directory_is_refused() -> TestResult {
    let (scratch, directory, rendered) = written()?;
    fs::remove_file(directory.join("manifest.json"))?;
    assert!(rendered.write(scratch.path()).is_err(), "reused");
    assert!(
        !directory.join("manifest.json").exists(),
        "the existing directory is not written"
    );
    Ok(())
}

/// Self-checks a capture whose only file holds `content` and which learned nothing:
/// `Some(kind)` on a leak (the directory is gone), `None` when it passes.
///
/// # Errors
///
/// Setup I/O errors, or a self-check error other than a leak.
fn unlearned_leak(content: &str) -> Result<Option<IdentifierKind>, Box<dyn Error>> {
    let scratch = TempDir::new()?;
    let rendered = Rendered {
        directory: "capture".to_owned(),
        files: [("item.txt".to_owned(), content.to_owned())].into(),
        manifest: json!({"items": [{"name": "item", "file": "item.txt"}]}),
        identifiers: Vec::new(),
        sources: Vec::new(),
        vocabulary: Vocabulary::default(),
    };
    let directory = rendered.write(scratch.path())?;
    match self_check(&directory, &rendered) {
        Ok(()) if directory.exists() => Ok(None),
        Ok(()) => Err("a passing self-check removed the directory".into()),
        Err(CaptureError::IdentifierLeaked {
            item,
            kind,
            hits: _,
        }) if item == "item.txt" && !directory.exists() => Ok(Some(kind)),
        Err(error) => Err(error.into()),
    }
}

/// A global or unique-local IPv6 address that nothing learned fails the self-check in any
/// spelling; documentation, link-local, loopback, multicast addresses, scope operators and
/// MACs pass (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when a spelling passes or a realistic shape fails.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn unlearned_global_ipv6_addresses_fail_the_self_check() -> TestResult {
    let global = Ipv6Addr::new(0x2a02, 0x06b8, 0x1c2d, 0, 0, 0, 0, 5).to_string();
    let short = Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 1).to_string();
    let local = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 1, 0, 0, 0, 1).to_string();
    for (case, content) in [
        ("plain", format!("peer {global}")),
        ("letter after", format!("{global}via")),
        ("colon before", format!("addr:{global}")),
        ("letters before", format!("via{global}")),
        ("two groups glued", format!("via{short}x")),
        ("unique local glued", format!("x{local}y")),
        ("percent-encoded", format!("u=%5B{global}%5D")),
        (
            "percent-encoded colons",
            format!("u={}", global.replace(':', "%3A")),
        ),
        (
            "lowercase escapes",
            format!("u={}", global.replace(':', "%3a")),
        ),
    ] {
        assert_eq!(
            unlearned_leak(&content)?,
            Some(IdentifierKind::Address),
            "{case} passed"
        );
    }
    for content in [
        "Core::Authenticator: ok; NDM::Something::x",
        "Network::Interface::Ipv6::Address",
        "route fe80::/64 via fe80::1 dev br0",
        "lo ::1/128 group ff02::1",
        "peer 2001:db8::5 lan 2001:db8:1:2300::1/64",
        "mac 02:00:00:00:07:01 at 12:34:56",
        "components wireguard sstp-server opkg",
    ] {
        assert_eq!(unlearned_leak(content)?, None, "a realistic shape failed");
    }
    Ok(())
}

/// A file that cannot be written removes the new capture directory and returns the error
/// (todo 4).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when the write succeeds or leaves the directory.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_failed_write_removes_the_new_directory() -> TestResult {
    let scratch = TempDir::new()?;
    let rendered = Rendered {
        directory: "capture".to_owned(),
        files: [("missing/item.json".to_owned(), "{}".to_owned())].into(),
        manifest: json!({"items": []}),
        identifiers: Vec::new(),
        sources: Vec::new(),
        vocabulary: Vocabulary::default(),
    };
    let written = rendered.write(scratch.path());
    assert!(written.is_err(), "the write succeeded");
    assert!(
        !scratch.path().join("capture").exists(),
        "the new directory is left behind"
    );
    Ok(())
}
