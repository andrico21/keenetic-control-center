//! Owner names never become firmware words.
//!
//! A name repeated as the key of name-keyed maps across `rci-root` and its `show rc`
//! answers is aliased, learned and listed, and appears nowhere in the written capture; a
//! serial is learned even when it repeats as a key.
//!
//! Assertion messages never carry a planted value.

use core::error::Error;
use std::fs;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::{
    anonymize::IdentifierKind,
    capture::{
        Captured, Item, Raw, RawBody, Rendered, Request, fidelity, render, self_check::self_check,
    },
};

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// A captured JSON answer.
fn answer(name: &str, request: Request, value: Value) -> Captured {
    (Item::new(name, request), Ok(RawBody(Raw::Json(value))))
}

/// A captured text answer.
fn text(name: &str, request: Request, value: &str) -> Captured {
    (
        Item::new(name, request),
        Ok(RawBody(Raw::Text(Zeroizing::new(value.to_owned())))),
    )
}

/// Renders `captured`, writes it, runs the fidelity check and the self-check, and returns
/// the rendering and every written file, lowercased and joined.
///
/// # Errors
///
/// Setup I/O errors, or a failing check.
fn passes(captured: &[Captured]) -> Result<(Rendered, String), Box<dyn Error>> {
    let rendered = render(captured, "KN-1811", "5.1.10");
    let scratch = TempDir::new()?;
    let directory = rendered.write(scratch.path())?;
    fidelity::check(&directory, captured, &rendered)?;
    self_check(&directory, &rendered)?;
    let mut all = String::new();
    for name in rendered.files.keys() {
        all.push_str(&fs::read_to_string(directory.join(name))?.to_lowercase());
    }
    Ok((rendered, all))
}

/// Whether `rendered` learned `value` as `kind`.
fn learned(rendered: &Rendered, value: &str, kind: IdentifierKind) -> bool {
    rendered
        .identifiers
        .iter()
        .any(|found| found.value == value && found.kind == kind)
}

/// A user name repeated as a map key is learned and written nowhere (todo 12).
///
/// The name is a key in `user`, the `users` of two servers and the `ip http proxy` map, in
/// `rci-root` and again in the `show rc` answers: it is aliased, learned and listed.
///
/// # Errors
///
/// Setup I/O errors or a failing check.
///
/// # Panics
///
/// Panics when the name is kept, not learned or counted as a firmware word.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn an_owner_name_repeated_as_a_map_key_is_learned_and_never_written() -> TestResult {
    for owner in ["Ownerq7Name", "plantedowner"] {
        let entry = json!({owner: {"tag": ["cli"]}});
        let server = |name: &str| json!({name: {"config": {"users": {owner: {"enabled": true}}}}});
        let mut root = json!({
            "user": entry,
            "ip": {"http": {"proxy": {owner: {"domain": true}}}},
        });
        for name in ["sstp-server", "vpn-server"] {
            if let (Some(target), Value::Object(more)) = (root.as_object_mut(), server(name)) {
                target.extend(more);
            }
        }
        let captured = vec![
            answer("rci-root", Request::Root, root),
            answer(
                "show-rc-user",
                Request::ShowRc(&["user"]),
                json!({"user": entry}),
            ),
            answer(
                "show-rc-sstp-server",
                Request::ShowRc(&["sstp-server"]),
                server("sstp-server"),
            ),
            answer(
                "show-rc-vpn-server",
                Request::ShowRc(&["vpn-server"]),
                server("vpn-server"),
            ),
            answer("whoami", Request::Get("whoami"), json!({"user": owner})),
            text(
                "show-log",
                Request::ShowLog,
                &format!("user {owner} signed in"),
            ),
        ];
        let (rendered, all) = passes(&captured)?;
        assert!(
            !rendered.vocabulary.holds(owner),
            "an owner name is a firmware word"
        );
        assert!(
            learned(&rendered, owner, IdentifierKind::User),
            "an owner name is not learned"
        );
        assert!(
            !all.contains(&owner.to_lowercase()),
            "an owner name is written"
        );
        assert!(
            all.contains("\"user\"") && all.contains("\"users\"") && all.contains("\"proxy\""),
            "the map keys of the firmware are kept"
        );
    }
    Ok(())
}

/// A client name repeated as a map key is learned and written nowhere (todo 12).
///
/// The name is a key of `known host`, `ip host` and an `object-group fqdn` map, in
/// `rci-root` and a `show rc` answer. Names that are firmware words (row fields of three
/// answers, a request word) keep every key, and an ordinary device name is still replaced.
///
/// # Errors
///
/// Setup I/O errors or a failing check.
///
/// # Panics
///
/// Panics when the client name is kept or a firmware key changes.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn a_client_name_repeated_as_a_map_key_is_learned_and_never_written() -> TestResult {
    let client = "PlantedClient";
    let hosts = json!({
        "known": {"host": {client: {"mac": "02:00:00:00:09:01"}}},
        "ip": {"host": {client: {"address": "192.0.2.9"}}},
        "object-group": {"fqdn": {client: {"include": ["example.com"]}}},
    });
    let rows: Vec<Value> = [client, "hostname", "Name", "iPhone13"]
        .into_iter()
        .zip(1_u8..)
        .map(|(name, index)| {
            json!({"mac": format!("02:00:00:00:09:0{index}"), "name": name, "hostname": name})
        })
        .collect();
    let captured = vec![
        answer("rci-root", Request::Root, hosts.clone()),
        answer("show-rc-ip-host", Request::ShowRc(&["ip host"]), hosts),
        answer(
            "show-ip-hotspot",
            Request::Show("show/ip/hotspot"),
            json!({"host": rows}),
        ),
        answer(
            "show-ip-arp",
            Request::Show("show/ip/arp"),
            json!([{"mac": "02:00:00:00:09:11", "name": "", "hostname": ""}]),
        ),
        answer(
            "show-ip-dhcp-bindings",
            Request::Show("show/ip/dhcp/bindings"),
            json!({"lease": [{"mac": "02:00:00:00:09:12", "name": "", "hostname": ""}]}),
        ),
        answer(
            "show-rc-user",
            Request::ShowRc(&["user"]),
            json!({"user": {"user": {"tag": ["cli"]}}}),
        ),
    ];
    let (rendered, all) = passes(&captured)?;
    for name in [client, "iPhone13"] {
        assert!(
            learned(&rendered, name, IdentifierKind::Host),
            "a client name is not learned"
        );
        assert!(
            !all.contains(&name.to_lowercase()),
            "a client name is written"
        );
    }
    for key in [
        "\"name\"",
        "\"hostname\"",
        "\"user\"",
        "\"known\"",
        "\"fqdn\"",
    ] {
        assert!(all.contains(key), "a firmware key is lost");
    }
    Ok(())
}

/// A serial is learned even when it repeats as a row key at three places (todo 12).
///
/// The `serial` field is zeroed and the serial is replaced in a log line too.
///
/// # Panics
///
/// Panics when the serial is kept or counted as a firmware word.
#[test]
fn a_serial_repeated_as_a_key_is_never_a_firmware_word() {
    let serial = "Sx4417planted";
    let captured = vec![
        answer(
            "show-identification",
            Request::Show("show/identification"),
            json!({"serial": serial, "a": [{serial: 1_u8}], "b": [{serial: 2_u8}], "c": [{serial: 3_u8}]}),
        ),
        text(
            "show-log",
            Request::ShowLog,
            &format!("device {serial} ready"),
        ),
    ];
    let rendered = render(&captured, "KN-1811", "5.1.10");
    assert!(
        !rendered.vocabulary.holds(serial),
        "a serial is a firmware word"
    );
    assert!(
        learned(&rendered, serial, IdentifierKind::Serial),
        "a serial is not learned"
    );
    let log = rendered
        .files
        .get("show-log.txt")
        .map_or_default(|written| written.to_lowercase());
    assert!(
        log.contains("device ") && !log.contains(&serial.to_lowercase()),
        "a serial is written in a log line"
    );
}
