//! Todo 16: `kcc entware packages`: listings, the update and the read-back changes, with
//! control characters stripped from what the router reports.

use kcc_i18n::keys;
use kcc_testkit::entware_ssh::Config;
use serde_json::json;

use super::{
    lab::{ROUTER, SshLab, refused},
    support::TestResult,
};

/// A version carrying terminal escapes and a bell, as a hostile package database could.
const HOSTILE_VERSION: &str = "1.3\u{1b}[2J\u{7}-1";

/// The same version as kcc prints it.
const CLEAN_VERSION: &str = "1.3[2J-1";

/// The userland of the package tests.
fn userland() -> Config {
    Config::default()
        .installed("curl", "8.0-1")
        .upgradable("curl", "8.1-1")
        .installable("nano", "7.2-1")
        .installed("zlib", HOSTILE_VERSION)
}

/// Todo 16: `packages list` and `upgradable` print the parsed packages (one JSON
/// document, control characters stripped in JSON and in text).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listings_print_parsed_packages_without_control_characters() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;

    let list = lab.json(&["entware", "packages", "list"])?;
    let upgradable = lab.json(&["entware", "packages", "upgradable"])?;
    let human = lab.confirmed(&["entware", "packages", "list"])?;

    assert_eq!(
        list,
        json!({"packages": [
            {"name": "curl", "version": "8.0-1", "new_version": null},
            {"name": "zlib", "version": CLEAN_VERSION, "new_version": null},
        ]})
    );
    assert_eq!(
        upgradable,
        json!({"packages": [{"name": "curl", "version": "8.0-1", "new_version": "8.1-1"}]})
    );
    assert_eq!(human.code, 0_i32, "{human:?}");
    assert!(human.stdout.contains(CLEAN_VERSION), "{human:?}");
    assert!(
        !human
            .stdout
            .chars()
            .any(|character| character.is_control() && character != '\n')
    );
    lab.shutdown().await
}

/// Todo 16: `update`, `install`, `upgrade` and `remove` change the router and print the
/// read-back versions; removing an absent package exits 4 and sends no mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_print_the_read_back_versions() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;

    let updated = lab.json(&["entware", "packages", "update"])?;
    let human_update = lab.confirmed(&["entware", "packages", "update"])?;
    let installed = lab.json(&["entware", "packages", "install", "nano"])?;
    let upgraded = lab.json(&["entware", "packages", "upgrade", "curl"])?;
    let removed = lab.json(&["entware", "packages", "remove", "nano"])?;

    assert_eq!(updated, json!({"router": ROUTER, "updated": true}));
    assert_eq!(human_update.code, 0_i32, "{human_update:?}");
    assert_eq!(
        installed,
        json!({"package": "nano", "before": null, "after": "7.2-1"})
    );
    assert_eq!(
        upgraded,
        json!({"package": "curl", "before": "8.0-1", "after": "8.1-1"})
    );
    assert_eq!(
        removed,
        json!({"package": "nano", "before": "7.2-1", "after": null})
    );
    let versions = lab.ssh.installed();
    assert_eq!(versions.get("curl").map(String::as_str), Some("8.1-1"));
    assert!(!versions.contains_key("nano"));
    let commands = lab.ssh.counters().commands;
    let absent = lab.confirmed(&["entware", "packages", "remove", "vim"])?;
    refused(
        &absent,
        4_i32,
        keys::CLI_ENTWARE_PACKAGE_NOT_INSTALLED,
        &[("router", ROUTER), ("name", "vim")],
    );
    assert_eq!(
        lab.ssh.counters().commands,
        commands + 1,
        "the listing only"
    );
    lab.shutdown().await
}
