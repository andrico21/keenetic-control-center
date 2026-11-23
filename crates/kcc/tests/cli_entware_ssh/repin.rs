//! Todo 16: a changed host key, the re-pin, revoke and disable.

use kcc_i18n::keys;
use serde_json::{Value, json};

use super::{
    lab::{ROUTER, SshLab, refused},
    support::TestResult,
};

/// Todo 16: a changed host key is refused until `ssh repin` pins it.
///
/// An operation exits 10 naming the new fingerprint, with no password and no key sent; a
/// bootstrap exits 5 asking for a re-pin; a re-pin of the pinned key exits 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_host_key_is_refused_until_it_is_repinned() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    drop(lab.ssh.replace_host_key());
    let before = lab.ssh.counters();
    let args = [("router", ROUTER)];

    let refused_list = lab.confirmed(&["entware", "packages", "list"])?;

    let (ticket, fingerprint) = lab.probe()?;
    refused(
        &refused_list,
        10_i32,
        keys::CLI_ENTWARE_SSH_HOSTKEY_MISMATCH,
        &[("router", ROUTER), ("value", &fingerprint)],
    );
    let after = lab.ssh.counters();
    assert_eq!(
        after.auth_attempts, before.auth_attempts,
        "nothing authenticated"
    );
    let bootstrap = lab.step("bootstrap", (&ticket, &fingerprint), &["--yes"])?;
    refused(
        &bootstrap,
        5_i32,
        keys::CLI_ENTWARE_SSH_REPIN_REQUIRED,
        &args,
    );
    assert_eq!(
        lab.ssh.counters().password_attempts,
        before.password_attempts
    );

    let (fresh, confirmed) = lab.probe()?;
    let repin = lab.step("repin", (&fresh, &confirmed), &["--yes", "--json"])?;

    assert_eq!(repin.code, 0_i32, "{repin:?}");
    let document: Value = serde_json::from_str(&repin.stdout)?;
    assert_eq!(
        document.get("fingerprint").and_then(Value::as_str),
        Some(confirmed.as_str())
    );
    assert_eq!(
        lab.json(&["entware", "packages", "list"])?,
        json!({"packages": []})
    );
    let (last, pinned) = lab.probe()?;
    let unchanged = lab.step("repin", (&last, &pinned), &["--yes"])?;
    refused(
        &unchanged,
        5_i32,
        keys::CLI_ENTWARE_SSH_KEY_UNCHANGED,
        &args,
    );
    lab.shutdown().await
}

/// Todo 16: `ssh revoke` removes kcc's line from the router and the local state;
/// afterwards an operation is refused as not enrolled (exit 10) without an SSH
/// connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_removes_the_key_line_and_the_enrolment() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;

    let revoked = lab.json(&["entware", "ssh", "revoke"])?;

    assert_eq!(revoked, json!({"router": ROUTER, "revoked": true}));
    assert!(!lab.ssh.authorized_keys().contains("kcc:lab-1"));
    let connections = lab.ssh.counters().connections;
    let list = lab.confirmed(&["entware", "packages", "list"])?;
    refused(
        &list,
        10_i32,
        keys::CLI_ENTWARE_SSH_NOT_ENROLLED,
        &[("router", ROUTER)],
    );
    assert_eq!(lab.ssh.counters().connections, connections);
    lab.shutdown().await
}

/// Todo 16: `ssh disable` forgets the local state without contacting the router; the
/// key line stays there and the result says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_forgets_locally_and_keeps_the_key_line() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    let before = lab.contacts();

    let disabled = lab.json(&["entware", "ssh", "disable"])?;

    assert_eq!(
        disabled,
        json!({"router": ROUTER, "disabled": true, "entware_key_still_authorized": true})
    );
    assert_eq!(lab.contacts(), before);
    assert!(lab.ssh.authorized_keys().contains("kcc:lab-1"));
    let list = lab.confirmed(&["entware", "packages", "list"])?;
    refused(
        &list,
        10_i32,
        keys::CLI_ENTWARE_SSH_NOT_ENROLLED,
        &[("router", ROUTER)],
    );
    lab.shutdown().await
}
