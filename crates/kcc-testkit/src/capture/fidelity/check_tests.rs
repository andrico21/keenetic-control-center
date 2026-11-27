//! The fidelity check against deliberately corrupted output: a key rewritten inside, a
//! changed kind and a changed configuration keyword each fail with exit code 4, and the
//! message names no value.

use core::error::Error;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::check;
use crate::capture::{CaptureError, Captured, Item, Raw, RawBody, Rendered, Request, render};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Planted values; none may appear in a message.
const PLANTED: [&str; 5] = [
    "PLANTED-HOST-7",
    "PLANTED-USER-13",
    "PLANTED-DESC-5",
    "PLANTED-SCHED-9",
    "Planted Home",
];

/// A captured JSON answer.
fn answer(name: &str, request: Request, value: Value) -> Captured {
    (Item::new(name, request), Ok(RawBody(Raw::Json(value))))
}

/// A capture holding a hotspot list, users with secrets, schedules and a configuration.
fn captured() -> Vec<Captured> {
    let row = |index: u8, name: &str| {
        json!({
            "mac": format!("02:00:00:00:07:0{index}"), "name": name, "hostname": name,
            "uptime": 5_u8, "interface": {"id": "Bridge0", "name": "Home", "description": "Planted Home"},
        })
    };
    let [host, user, description, schedule, _] = PLANTED;
    let config = format!(
        "! $$$ Model: KN-1811\ninterface Bridge0\n    description {description}\n!\n\
         ip name-server 192.0.2.53\nip host {host} 192.0.2.7\n\
         ip route 192.0.2.0 255.255.255.0 Bridge0 auto !Office route\n"
    );
    vec![
        answer(
            "rci-root",
            Request::Root,
            json!({"ip": {"route": [{"network": "192.0.2.0", "comment": "Office route"}]}}),
        ),
        answer(
            "show-ip-hotspot",
            Request::Show("show/ip/hotspot"),
            json!({"host": [row(1, host), row(2, "PLANTED-HOST-8"), row(3, "PLANTED-HOST-9")]}),
        ),
        answer(
            "show-rc-user",
            Request::ShowRc(&["user"]),
            json!({"user": {user: {"password": {"md5": "abc", "nt": 12_u8}}, "service": {"tag": ["cli"]}}}),
        ),
        answer(
            "show-schedule",
            Request::Show("show/schedule"),
            json!({schedule: {"action": [{"left": 1_u8}]}}),
        ),
        (
            Item::new("running-config", Request::RunningConfig),
            Ok(RawBody(Raw::Config(Zeroizing::new(config)))),
        ),
    ]
}

/// Writes `rendered` after `corrupt` changed it and runs the fidelity check; the message
/// of a failure, `None` on success.
///
/// # Errors
///
/// Setup I/O errors, an unexpected error or a failure that kept the directory.
fn checked(corrupt: impl FnOnce(&mut Rendered)) -> Result<Option<(u8, String)>, Box<dyn Error>> {
    let captured = captured();
    let mut rendered = render(&captured, "KN-1811", "5.1.10");
    corrupt(&mut rendered);
    let scratch = TempDir::new()?;
    let directory = rendered.write(scratch.path())?;
    match check(&directory, &captured, &rendered) {
        Ok(()) if directory.exists() => Ok(None),
        Ok(()) => Err("a passing check removed the directory".into()),
        Err(
            error @ CaptureError::SchemaChanged {
                item: _,
                at: _,
                expected: _,
                found: _,
            },
        ) if !directory.exists() => Ok(Some((error.exit_code(), error.to_string()))),
        Err(error) => Err(error.into()),
    }
}

/// Replaces `from` by `to` in the written file `name`.
fn replace(rendered: &mut Rendered, name: &str, from: &str, to: &str) {
    if let Some(content) = rendered.files.get_mut(name) {
        *content = content.replace(from, to);
    }
}

/// An anonymized capture keeps its schema: aliases of name-keyed maps, redacted secrets,
/// rewritten values and a learned comment that holds a keyword pass (todo 12).
///
/// # Errors
///
/// Setup I/O errors or an unexpected failure.
#[test]
fn an_anonymized_capture_keeps_its_schema() -> TestResult {
    match checked(|_| {})? {
        None => Ok(()),
        Some((code, message)) => Err(format!("exit {code}: {message}").into()),
    }
}

/// A corrupted output fails with exit code 4 and a value-free message naming the item and
/// the place; a name of a name-keyed map written as it was fails too (todo 12).
///
/// # Errors
///
/// Setup I/O errors.
///
/// # Panics
///
/// Panics when a corruption passes, the code is not 4 or a planted value is named.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_corrupted_output_fails_with_exit_4_without_a_value() -> TestResult {
    let hotspot = "show-ip-hotspot.json";
    let [_, user, ..] = PLANTED;
    let cases: [(&str, &str, &str, &str, &[&str]); 5] = [
        (
            "a learned value inside a key",
            hotspot,
            "\"hostname\"",
            "\"hostssid-1\"",
            &["show-ip-hotspot.json", "$.host[].hostname"],
        ),
        (
            "a whole key aliased",
            hotspot,
            "\"uptime\"",
            "\"ssid-1\"",
            &["$.host[].uptime", "absent"],
        ),
        (
            "a changed kind",
            hotspot,
            "\"uptime\": 5",
            "\"uptime\": \"5\"",
            &["$.host[].uptime", "number", "string"],
        ),
        (
            "a map entry's name written as it was",
            "show-rc-user.json",
            "\"user-1\"",
            &format!("\"{user}\""),
            &["show-rc-user.json", "$.user.*"],
        ),
        (
            "a changed configuration keyword",
            "running-config.txt",
            "name-server",
            "ssid-1-server",
            &["running-config.txt", "line "],
        ),
    ];
    for (case, file, from, to, named) in cases {
        let outcome = checked(|rendered| replace(rendered, file, from, to))?;
        let Some((code, message)) = outcome else {
            return Err(format!("{case} passed the fidelity check").into());
        };
        assert_eq!(code, 4, "{case}: exit code");
        for part in named {
            assert!(message.contains(part), "{case}: {message} names {part}");
        }
        for planted in PLANTED {
            assert!(
                !message.to_lowercase().contains(&planted.to_lowercase()),
                "{case}: a planted value is in the message"
            );
        }
    }
    Ok(())
}
