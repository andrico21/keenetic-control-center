//! The fidelity check compares the keys themselves: a firmware key seen once keeps its
//! spelling even when a client has that name, rewriting it fails, and a difference in
//! count names both counts.
//!
//! Assertion messages never carry a planted value.

use core::error::Error;

use serde_json::{Value, json};
use tempfile::TempDir;

use super::check;
use crate::capture::{CaptureError, Captured, Item, Raw, RawBody, Rendered, Request, render};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// The exit code and message of a failed check, `None` when it passed.
type Outcome = Option<(u8, String)>;

/// A captured JSON answer.
fn answer(name: &str, request: Request, value: Value) -> Captured {
    (Item::new(name, request), Ok(RawBody(Raw::Json(value))))
}

/// `show version` with a key seen once, and three clients, one named like that key.
fn captured() -> Vec<Captured> {
    let rows: Vec<Value> = ["release", "PLANTED-HOST-3", "PLANTED-HOST-4"]
        .into_iter()
        .zip(1_u8..)
        .map(|(name, index)| json!({"mac": format!("02:00:00:00:08:0{index}"), "name": name}))
        .collect();
    vec![
        answer(
            "show-version",
            Request::Show("show/version"),
            json!({"release": "5.1.10", "title": "5.1.10"}),
        ),
        answer(
            "show-ip-hotspot",
            Request::Show("show/ip/hotspot"),
            json!({"host": rows}),
        ),
    ]
}

/// Renders [`captured`], lets `corrupt` change the rendering, writes it and checks it:
/// the exit code and message of a failure, `None` on success.
///
/// # Errors
///
/// Setup I/O errors or an unexpected error.
fn checked(corrupt: impl FnOnce(&mut Rendered)) -> Result<(Rendered, Outcome), Box<dyn Error>> {
    let captured = captured();
    let mut rendered = render(&captured, "KN-1811", "5.1.10");
    corrupt(&mut rendered);
    let scratch = TempDir::new()?;
    let directory = rendered.write(scratch.path())?;
    let outcome = match check(&directory, &captured, &rendered) {
        Ok(()) => None,
        Err(
            error @ CaptureError::SchemaChanged {
                item: _,
                at: _,
                expected: _,
                found: _,
            },
        ) if !directory.exists() => Some((error.exit_code(), error.to_string())),
        Err(error) => return Err(error.into()),
    };
    Ok((rendered, outcome))
}

/// A client named like a firmware key that occurs once does not rewrite that key, and a
/// rewritten key fails with exit code 4 (todo 12).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when the key changes, the check passes a rewritten key or names a value.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_rare_firmware_key_named_like_a_client_is_kept_and_checked() -> TestResult {
    let (rendered, outcome) = checked(|_| {})?;
    let version: Value = serde_json::from_str(
        rendered
            .files
            .get("show-version.json")
            .map_or("null", String::as_str),
    )?;
    assert!(
        version.get("release").is_some(),
        "the firmware key is rewritten"
    );
    assert_eq!(outcome, None, "the anonymized capture passes");
    let (_, corrupted) = checked(|written| {
        if let Some(content) = written.files.get_mut("show-version.json") {
            *content = content.replace("\"release\"", "\"host-1\"");
        }
    })?;
    let Some((code, message)) = corrupted else {
        return Err("a rewritten key passed the fidelity check".into());
    };
    assert_eq!(code, 4, "exit code");
    assert!(
        message.contains("show-version.json") && message.contains("$.*"),
        "the message names the file and masks the learned key: {message}"
    );
    assert!(
        !message.to_lowercase().contains("planted"),
        "a planted value is in the message"
    );
    Ok(())
}

/// When only the count at a path differs, the message names both counts (todo 12).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when the difference passes or a count is missing.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_count_difference_names_both_counts() -> TestResult {
    let (_, outcome) = checked(|rendered| {
        if let Some(content) = rendered.files.get_mut("show-ip-hotspot.json") {
            let mut parsed: Value = serde_json::from_str(content).unwrap_or_default();
            if let Some(rows) = parsed.get_mut("host").and_then(Value::as_array_mut) {
                drop(rows.pop());
            }
            *content = parsed.to_string();
        }
    })?;
    let Some((code, message)) = outcome else {
        return Err("a missing row passed the fidelity check".into());
    };
    assert_eq!(code, 4, "exit code");
    assert!(
        message.contains("$.host[]") && message.contains("x3") && message.contains("x2"),
        "the message names both counts: {message}"
    );
    Ok(())
}
