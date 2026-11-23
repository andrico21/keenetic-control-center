//! Positive controls: each suite's exact code path runs to the end against the fakes, so
//! the refusal proofs cannot pass by a suite that refuses everything.
#![expect(clippy::panic_in_result_fn, reason = "twin tests fail by asserting")]

use std::{fs, process};

use kcc_testkit::entware_ssh::{Config, Service};
use serde_json::Value;

use super::{
    TestResult, evidence,
    lab::{DRIVE, Lab},
    refusal::Suite,
};

/// The evidence file `name` of `lab`.
fn record(lab: &Lab, name: &str) -> TestResult<Value> {
    let path = lab.reach().evidence.join(name);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

/// Todo 19: the probe needs no write flag, sends no write and records the Entware facts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_records_the_entware_facts_read_only() -> TestResult {
    let lab = Lab::start(true).await?;
    Suite::Probe
        .run(
            &lab,
            &[("KCC_LIVE_ALLOW_WRITE", ""), ("KCC_LIVE_ENTWARE_SETUP", "")],
        )
        .await?;
    let capture = record(&lab, evidence::PROBE)?;
    assert_eq!(
        capture.pointer("/version/arch"),
        Some(&Value::from("aarch64"))
    );
    assert_eq!(
        capture.pointer("/components/opkg_listed"),
        Some(&Value::Bool(true)),
        "{capture}"
    );
    let media = capture
        .pointer("/media/entries")
        .and_then(Value::as_array)
        .ok_or("no media")?;
    assert!(!media.is_empty(), "{capture}");
    assert!(capture.pointer("/log/kind").is_some(), "{capture}");
    assert!(capture.pointer("/status/drives").is_some(), "{capture}");
    assert_eq!(lab.writes(), Vec::<String>::new(), "writes sent");
    lab.shutdown().await
}

/// Todo 19: on an eligible drive the setup suite runs the guided setup and records the
/// installer's log markers; it never saves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_installs_on_an_eligible_drive_and_records_the_markers() -> TestResult {
    let lab = Lab::start(true).await?;
    Suite::Setup.run(&lab, &[]).await?;
    let capture = record(&lab, evidence::SETUP)?;
    assert_eq!(
        capture.pointer("/job/status"),
        Some(&Value::from("completed"))
    );
    let markers = capture
        .pointer("/markers")
        .and_then(Value::as_array)
        .ok_or("no markers")?;
    assert!(
        markers
            .iter()
            .filter_map(Value::as_str)
            .any(|line| line.contains("[5/5]")),
        "{capture}"
    );
    let commands = lab.commands();
    assert!(
        commands
            .iter()
            .any(|line| line.starts_with(&format!("opkg disk {DRIVE} "))),
        "{commands:?}"
    );
    assert!(
        commands
            .iter()
            .all(|line| !line.contains("configuration save")),
        "{commands:?}"
    );
    lab.shutdown().await
}

/// A random password, built at run time.
fn password() -> String {
    format!("pw-{:x}", process::id())
}

/// Todo 19: the SSH suite enrols, installs and removes the package, checks one service and
/// revokes, leaving no key line behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_suite_enrols_exercises_and_revokes() -> TestResult {
    let userland = Config::default()
        .installable("nano", "7.2-1")
        .service("S51dropbear", Service::new("dropbear").running());
    let lab = Lab::start(true)
        .await?
        .with_ssh(userland, &password())
        .await?;
    Suite::Ssh.run(&lab, &[]).await?;
    let ssh = lab.ssh.as_ref().ok_or("no ssh")?;
    assert_eq!(ssh.handle.authorized_keys().trim(), "", "key left behind");
    assert!(!ssh.handle.installed().contains_key("nano"), "nano left");
    let capture = record(&lab, evidence::SSH)?;
    assert_eq!(capture.pointer("/port"), Some(&Value::from(ssh.port)));
    assert_eq!(capture.pointer("/revoked"), Some(&Value::Bool(true)));
    assert_eq!(
        capture.pointer("/service/state"),
        Some(&Value::from("running")),
        "{capture}"
    );
    lab.shutdown().await
}

/// Todo 19: a package the router already has is never removed; the failing step still
/// revokes kcc's key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_suite_keeps_an_installed_package_and_still_revokes() -> TestResult {
    let userland = Config::default().installed("nano", "7.2-1");
    let lab = Lab::start(true)
        .await?
        .with_ssh(userland, &password())
        .await?;
    let outcome = Suite::Ssh.run(&lab, &[]).await;
    assert!(outcome.is_err(), "an installed package passed");
    let ssh = lab.ssh.as_ref().ok_or("no ssh")?;
    assert_eq!(
        ssh.handle.installed().get("nano").map(String::as_str),
        Some("7.2-1")
    );
    assert_eq!(ssh.handle.authorized_keys().trim(), "", "key left behind");
    let capture = record(&lab, evidence::SSH)?;
    assert_eq!(capture.pointer("/revoked"), Some(&Value::Bool(true)));
    lab.shutdown().await
}
