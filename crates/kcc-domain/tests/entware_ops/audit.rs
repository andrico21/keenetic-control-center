//! Audit entries of the operations: router, actor, operation, name, outcome, the output's
//! byte count and SHA-256, and never the output itself.

use core::fmt::Write as _;
use std::fs;

use kcc_app::audit::chain_files;
use kcc_domain::entware::ssh::ops::ServiceVerb;
use sha2::{Digest as _, Sha256};

use crate::{
    harness::param,
    rig::{Op, Rig},
    support::TestResult,
};

/// The installed listing the fake prints for the rig's userland.
const LISTING: &str = "dropbear - 2022.83-1\nnano - 7.2-1\npinned - 1.0-1\n";

/// Lowercase hex SHA-256 of `text`.
fn sha256(text: &str) -> TestResult<String> {
    let mut hex = String::new();
    for byte in Sha256::digest(text.as_bytes()) {
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

/// Todo 11: a listing's entry names the router, the actor and the operation, and carries
/// the byte count and SHA-256 of exactly the output the command printed.
#[tokio::test]
async fn an_entry_carries_the_output_digest() -> TestResult {
    let rig = Rig::start().await?;
    drop(rig.ok(Op::List).await?);
    let entries = rig.harness().audited("entware.ssh.packages_list")?;
    let [entry] = entries.as_slice() else {
        return Err(format!("{} listing entries", entries.len()).into());
    };
    assert_eq!(entry.router.as_deref(), Some("router"));
    assert_eq!(entry.actor.id, "alice");
    assert_eq!(entry.outcome, "success");
    assert_eq!(param(entry, "output_bytes"), LISTING.len());
    assert_eq!(param(entry, "output_sha256"), sha256(LISTING)?.as_str());
    Ok(())
}

/// Todo 11: the digest covers every command of the operation in order, standard error
/// included: a failed install's entry digests the listing, the install's error text and
/// the read-back listing.
#[tokio::test]
async fn the_digest_covers_every_command_and_standard_error() -> TestResult {
    let rig = Rig::start().await?;
    drop(
        rig.run(Op::Install("absent"))
            .await?
            .err()
            .ok_or("installed")?,
    );
    let output = format!(
        "{LISTING}Unknown package 'absent'.\nCollected errors:\n * opkg_install_cmd: \
         Cannot install package absent.\n{LISTING}"
    );
    let entries = rig.harness().audited("entware.ssh.install")?;
    let entry = entries.first().ok_or("no install entry")?;
    assert_eq!(param(entry, "output_bytes"), output.len());
    assert_eq!(param(entry, "output_sha256"), sha256(&output)?.as_str());
    Ok(())
}

/// Todo 11: after listings, a status, an action and package changes, the audit files hold
/// none of the output text: no listing line, no rc.func line.
#[tokio::test]
async fn audit_files_hold_no_output_text() -> TestResult {
    let rig = Rig::start().await?;
    for op in [
        Op::List,
        Op::Upgradable,
        Op::Services,
        Op::Status("S51dropbear"),
        Op::Action("S50nginx", ServiceVerb::Start),
        Op::Update,
        Op::Install("htop"),
        Op::Upgrade("nano"),
    ] {
        drop(rig.ok(op).await?);
    }
    let mut text = String::new();
    for file in chain_files(&rig.harness().fixture().state_dir())? {
        text.push_str(&String::from_utf8_lossy(&fs::read(file)?));
    }
    for needle in [
        "nano - 7.2-1",
        "7.2-1 - 7.4-1",
        "alive.",
        "Checking",
        "Starting",
        "Installing",
        "Upgrading",
        "Packages.gz",
    ] {
        assert!(!text.contains(needle), "the audit holds {needle:?}");
    }
    for action in [
        "entware.ssh.services_list",
        "entware.ssh.service_status",
        "entware.ssh.service_start",
        "entware.ssh.update",
        "entware.ssh.install",
    ] {
        let entries = rig.harness().audited(action)?;
        let entry = entries.first().ok_or(action)?;
        let digest = param(entry, "output_sha256");
        let hex = digest.as_str().ok_or(action)?;
        assert_eq!(hex.len(), 64, "{action}");
        assert!(param(entry, "output_bytes").as_u64() > Some(0), "{action}");
    }
    Ok(())
}
