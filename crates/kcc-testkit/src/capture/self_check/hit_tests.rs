//! The diagnostics of a refused self-check: every hit names its file, its place, the kind
//! and source of the learned value and the matched length, and never a value.
//!
//! Assertion messages never carry a planted value.

use core::error::Error;

use kcc_rci::RciError;
use serde_json::json;
use tempfile::TempDir;

use super::{hits::LeakHit, self_check};
use crate::{
    anonymize::{Identifier, IdentifierKind, vocabulary::Vocabulary},
    capture::{CaptureError, Captured, Item, Raw, RawBody, Rendered, Request, render},
};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// A planted client name, learned from a `name` key.
const NAME: &str = "PLANTED-NAME-41";

/// Self-checks `rendered` below a fresh directory and returns the refusal's hits and its
/// Display text.
///
/// # Errors
///
/// Setup I/O errors, a passing self-check, or an error other than a leak.
fn refused(rendered: &Rendered) -> Result<(Vec<LeakHit>, String), Box<dyn Error>> {
    let scratch = TempDir::new()?;
    let directory = rendered.write(scratch.path())?;
    match self_check(&directory, rendered) {
        Err(error) => {
            let text = error.to_string();
            match error {
                CaptureError::IdentifierLeaked {
                    item: _,
                    kind: _,
                    hits,
                } => Ok((hits, text)),
                CaptureError::Rci(_)
                | CaptureError::SerialMissing
                | CaptureError::SerialNotAllowed
                | CaptureError::Io(_)
                | CaptureError::IdentifiersInsideCapture
                | CaptureError::SchemaChanged {
                    item: _,
                    at: _,
                    expected: _,
                    found: _,
                } => Err(text.into()),
            }
        }
        Ok(()) => Err("the self-check passed".into()),
    }
}

/// Whether `text` shows the planted value in any case, or a part of it.
fn shows_value(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains(&NAME.to_lowercase()) || lower.contains("planted")
}

/// A refusal names every hit's file, place, kind, source, value class and length, never the
/// value (todo 12).
///
/// For the manifest and for a data file: the JSON path or line, the source item and key
/// path of the learned value, and the manifest string with the match masked.
///
/// # Errors
///
/// Setup I/O errors or a passing self-check.
///
/// # Panics
///
/// Panics when a field is missing or the value is shown.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_refusal_names_every_hit_without_the_value() -> TestResult {
    let captured: Vec<Captured> = vec![
        (
            Item::new("show-ip-arp", Request::Show("show/ip/arp")),
            Ok(RawBody(Raw::Json(json!([
                {"name": "printer", "ip": "192.0.2.7"},
                {"name": NAME, "ip": "192.0.2.8"}
            ])))),
        ),
        (
            Item::new(
                &format!("show-interface-stat-{NAME}"),
                Request::InterfaceStat(NAME.to_owned()),
            ),
            Err(RciError::NotFound),
        ),
    ];
    let mut rendered = render(&captured, "KN-1811", "5.1.3");
    drop(rendered.files.insert(
        "show-log.txt".to_owned(),
        format!("first line\nlease for {}\n", NAME.to_lowercase()),
    ));
    let (hits, text) = refused(&rendered)?;
    assert!(!shows_value(&text), "the Display shows the value");
    let manifest = hits
        .iter()
        .find(|hit| hit.file == "manifest.json" && hit.location == "$.items[1].name")
        .ok_or("no hit on the item name")?;
    assert_eq!(manifest.kind, IdentifierKind::Host, "kind");
    assert_eq!(manifest.source, "show-ip-arp[1].name", "source");
    assert_eq!(manifest.class, "len15/mixed", "value class");
    assert_eq!(manifest.length, Some(15), "matched length");
    assert_eq!(
        manifest.shown.as_deref(),
        Some("show-interface-stat-<MATCH>"),
        "masked manifest string"
    );
    let log = hits
        .iter()
        .find(|hit| hit.file == "show-log.txt")
        .ok_or("no data file hit")?;
    assert_eq!(log.location, "line 2", "line number");
    assert_eq!(log.length, Some(15), "matched length");
    assert_eq!(log.shown, None, "a data file line is never shown");
    for field in [
        "file=manifest.json",
        "at=$.items[1].name",
        "kind=host",
        "source=show-ip-arp[1].name",
        "value=len15/mixed",
        "matched-len=15",
        "text=show-interface-stat-<MATCH>",
        "file=show-log.txt",
        "at=line 2",
    ] {
        assert!(text.contains(field), "the Display lacks {field}");
    }
    Ok(())
}

/// A manifest string whose rest is not made of fixed words is shown as `<redacted>`; a
/// matched object key is named as the key of its object (todo 12).
///
/// # Errors
///
/// Setup I/O errors or a passing self-check.
///
/// # Panics
///
/// Panics when the rest is shown or the key location is wrong.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn router_words_beside_a_match_are_redacted() -> TestResult {
    let rendered = Rendered {
        directory: "capture".to_owned(),
        files: [("item.json".to_owned(), "{}".to_owned())].into(),
        manifest: json!({"items": [
            {"name": "item", "file": "item.json", "skipped": format!("router said {NAME} twice")},
            {"name": "other", NAME: 1_u8}
        ]}),
        identifiers: vec![Identifier {
            value: NAME.to_owned(),
            kind: IdentifierKind::Host,
        }],
        sources: vec!["show-ip-arp[0].name".to_owned()],
        vocabulary: Vocabulary::default(),
    };
    let (hits, text) = refused(&rendered)?;
    assert!(!shows_value(&text), "the Display shows the value");
    assert!(!text.contains("router said"), "router words are shown");
    let skipped = hits
        .iter()
        .find(|hit| hit.location == "$.items[0].skipped")
        .ok_or("no skipped hit")?;
    assert_eq!(skipped.shown.as_deref(), Some("<redacted>"), "redacted");
    let key = hits
        .iter()
        .find(|hit| hit.location == "key of $.items[1]")
        .ok_or("no key hit")?;
    assert_eq!(key.length, Some(15), "matched length");
    Ok(())
}
