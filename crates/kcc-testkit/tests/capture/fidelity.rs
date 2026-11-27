//! Fidelity of `kcc-capture` against the fake router: names that are firmware words keep
//! the schema intact.
//!
//! Assertion messages never carry a planted value.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking and is not rendered API documentation"
)]

use core::net::SocketAddr;
use std::fs;

use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    leaks::CAPTURE,
    tests::{NAME, TestResult, run_capture},
};

/// A planted `show rc user` key.
const USER: &str = "PLANTED-USER-41";

/// Names that are firmware words are not learned and keep the schema (todo 12).
///
/// A client named like a row field (one the answers hold in rows at three places) and a
/// user named like a firmware keyword: the written rows keep every key, the names stay as
/// they are and are not listed; other names are still replaced and listed.
#[tokio::test(flavor = "multi_thread")]
async fn names_that_are_firmware_words_keep_the_schema() -> TestResult {
    let rows: Vec<Value> = [("hostname", 1_u8), (NAME, 2), ("PLANTED-HOST-42", 3)]
        .into_iter()
        .map(|(name, index)| {
            json!({"mac": format!("02:00:00:00:07:0{index}"), "ip": format!("192.0.2.7{index}"),
                   "name": name, "hostname": "PLANTED-HOST-43"})
        })
        .collect();
    let (address, handle) = FakeRouter::builder(Profile::default())
        .show_fixture("ip/arp", Value::Array(rows.clone()))
        .show_fixture("ip/hotspot", Value::Array(rows.clone()))
        .show_fixture("ip/dhcp/bindings", Value::Array(rows))
        .rc_fixture(
            "/user",
            json!({"service": {"tag": ["cli"]}, USER: {"tag": ["cli"]}}),
        )
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let scratch = TempDir::new()?;
    let identifiers = scratch.path().join("identifiers.txt");
    let output = run_capture(
        address,
        scratch.path(),
        &[
            "--identifiers-out".to_owned(),
            identifiers.display().to_string(),
        ],
    )
    .await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(0_i32), "capture passes");
    let directory = scratch.path().join("out").join(CAPTURE);
    let arp: Value =
        serde_json::from_str(&fs::read_to_string(directory.join("show-ip-arp.json"))?)?;
    let written: Vec<&Value> = arp
        .as_array()
        .map_or_else(Vec::new, |found| found.iter().collect());
    assert_eq!(written.len(), 3, "every row is written");
    for row in &written {
        let mut keys: Vec<&str> = row.as_object().map_or_else(Vec::new, |members| {
            members.keys().map(String::as_str).collect()
        });
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["hostname", "ip", "mac", "name"],
            "a row keeps its keys"
        );
    }
    assert_eq!(
        written.first().and_then(|row| row.get("name")),
        Some(&json!("hostname")),
        "a client named like a row field keeps its name"
    );
    let users = fs::read_to_string(directory.join("show-rc-user.json"))?;
    assert!(
        users.contains("\"service\""),
        "a user named like a keyword keeps its key"
    );
    let listed = fs::read_to_string(&identifiers)?;
    for word in ["hostname", "service"] {
        assert!(
            !listed.lines().any(|line| line == word),
            "a firmware word is listed"
        );
    }
    for planted in [NAME, "PLANTED-HOST-42", "PLANTED-HOST-43", USER] {
        assert!(
            listed.lines().any(|line| line == planted),
            "a planted name is not listed"
        );
    }
    let mut all = fs::read_to_string(directory.join("show-ip-arp.json"))?.to_lowercase();
    all.push_str(&users.to_lowercase());
    for planted in [NAME, "PLANTED-HOST-42", "PLANTED-HOST-43", USER] {
        assert!(
            !all.contains(&planted.to_lowercase()),
            "a planted name survived"
        );
    }
    Ok(())
}
