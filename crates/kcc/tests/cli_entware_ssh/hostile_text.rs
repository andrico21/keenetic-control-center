//! Todo 16: hostile router-reported text is printed without its hostile characters.
//!
//! Terminal escapes, a bell, a NUL and a right-to-left override in the upgradable
//! listing, the read-back change lines and the service log: the human output and the
//! `--json` document carry none of them, and the visible text survives.

use kcc_testkit::{
    entware_install::record,
    entware_ssh::{Config, Service},
};
use serde_json::{Value, json};

use super::{
    lab::SshLab,
    support::{Run, TestResult},
};

/// What a hostile package database or router log may embed.
const HOSTILE: &str = "\u{1b}[31m\u{7}\u{0}\u{202e}";

/// `head` and `tail` around the hostile characters.
fn hostile(head: &str, tail: &str) -> String {
    format!("{head}{HOSTILE}{tail}")
}

/// The same text as kcc may print it: the visible part of the escape stays.
fn shown(head: &str, tail: &str) -> String {
    format!("{head}[31m{tail}")
}

/// Whether `character` can move the cursor, ring, cut or reorder what a terminal shows.
const fn unsafe_character(character: char) -> bool {
    (character.is_control() && character != '\n')
        || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Asserts that `run` succeeded and printed `visible` and no unsafe character.
fn printed(run: &Run, visible: &str) {
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout.contains(visible),
        "expected {visible:?}: {run:?}"
    );
    assert!(
        !run.stdout.chars().any(unsafe_character),
        "unsafe character printed: {run:?}"
    );
}

/// Todo 16: the upgradable `new_version` and the before and after versions of
/// `install`, `upgrade` and `remove` are printed without the hostile characters, in text
/// and in JSON.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn package_versions_are_printed_without_hostile_characters() -> TestResult {
    let config = Config::default()
        .installed("curl", "8.0-1")
        .upgradable("curl", &hostile("8.1", "-1"))
        .installable("nano", &hostile("7.2", "-1"))
        .installed("zlib", &hostile("1.3", "-1"));
    let lab = SshLab::spawn("admin", config).await?;
    lab.enrol()?;

    let upgradable = lab.confirmed(&["entware", "packages", "upgradable"])?;
    let listed = lab.json(&["entware", "packages", "upgradable"])?;
    let installed = lab.confirmed(&["entware", "packages", "install", "nano"])?;
    let removed = lab.json(&["entware", "packages", "remove", "nano"])?;
    let upgraded = lab.json(&["entware", "packages", "upgrade", "curl"])?;
    let gone = lab.confirmed(&["entware", "packages", "remove", "zlib"])?;

    printed(&upgradable, &shown("8.1", "-1"));
    assert_eq!(
        listed,
        json!({"packages": [{"name": "curl", "version": "8.0-1",
                             "new_version": shown("8.1", "-1")}]})
    );
    printed(&installed, &shown("7.2", "-1"));
    assert_eq!(
        removed,
        json!({"package": "nano", "before": shown("7.2", "-1"), "after": null})
    );
    assert_eq!(
        upgraded,
        json!({"package": "curl", "before": "8.0-1", "after": shown("8.1", "-1")})
    );
    printed(&gone, &shown("1.3", "-1"));
    lab.shutdown().await
}

/// Todo 16: the message of a service's log record is printed without the hostile
/// characters, in text and in JSON; a hostile level becomes the fixed word `other`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_log_records_are_printed_without_hostile_characters() -> TestResult {
    let config = Config::default().service("S51dropbear", Service::new("dropbear").running());
    let lab = SshLab::spawn("admin", config).await?;
    let message = format!("dropbear[1]: {}", hostile("alert", "text"));
    let mut entry = record(&hostile("W", ""), &message);
    let body = entry
        .get_mut("message")
        .and_then(Value::as_object_mut)
        .ok_or("no record body")?;
    drop(body.insert("level".to_owned(), json!(hostile("warning", ""))));
    lab.base.fake.insert_log(10, entry);

    let human = lab.confirmed(&["entware", "services", "log", "S51dropbear"])?;
    let document = lab.json(&["entware", "services", "log", "S51dropbear"])?;

    printed(&human, &format!("other {}", shown("alert", "text")));
    let records = document
        .get("records")
        .and_then(Value::as_array)
        .ok_or("no records")?;
    let fields = records
        .iter()
        .map(|shown_record| (shown_record.get("level"), shown_record.get("message")))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [(Some(&json!("other")), Some(&json!(shown("alert", "text"))))],
        "{document}"
    );
    assert_eq!(document.get("service"), Some(&json!("S51dropbear")));
    lab.shutdown().await
}
