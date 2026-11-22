//! Bootstrap: one marked line, the Active state, the default-password flag and the
//! half-done state a dropped connection leaves.

use kcc_app::entware_ssh::state::EnrolmentState;
use kcc_domain::entware::ssh::error::EntwareError;
use kcc_ssh::keys::HostKeyPin;
use kcc_testkit::{
    entware_ssh::{Config, DEFAULT_PASSWORD, Fault},
    model::Firmware,
};
use serde_json::json;

use crate::{
    harness::{Harness, marker, param},
    support::{PROFILES, TestResult},
};

/// Todo 9: probe and bootstrap install exactly one `kcc:<id>` line and activate.
///
/// The probe reports the fake's host key without authenticating; the bootstrap saves the
/// pin, the router host and the key, marks the enrolment Active and audits both steps
/// with public values.
#[tokio::test]
async fn bootstrap_installs_one_marked_line_and_activates() -> TestResult {
    for firmware in PROFILES {
        let harness = Harness::start(firmware, Config::default()).await?;
        let presented = HostKeyPin::from_openssh(&harness.ssh()?.host_key().to_openssh()?)?;
        let ticket = harness.probe().await?;
        assert_eq!(ticket.fingerprint, presented.fingerprint());
        assert_eq!(ticket.host_key, presented.to_openssh()?);
        assert_eq!(
            harness.counters()?.auth_attempts,
            0,
            "a probe never signs in"
        );
        let enrolled = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await??;
        assert_eq!(enrolled.fingerprint, ticket.fingerprint);
        assert_eq!(harness.kcc_lines()?.len(), 1);
        let record = harness.record()?.ok_or("no record")?;
        assert_eq!(record.state, EnrolmentState::Active);
        assert_eq!(record.host_key.as_deref(), Some(ticket.host_key.as_str()));
        assert_eq!(
            record.fingerprint.as_deref(),
            Some(ticket.fingerprint.as_str())
        );
        assert_eq!(record.router_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(record.enrolled_by.as_deref(), Some("alice"));
        assert!(record.enrolled_at.is_some());
        assert!(
            harness.private_key()?.is_some(),
            "the key is sealed on disk"
        );
        let probe = harness.audited("entware.ssh.probe")?;
        assert_eq!(probe.len(), 1);
        let probed = probe.first().ok_or("no probe entry")?;
        assert_eq!(probed.outcome, "success");
        assert_eq!(probed.router.as_deref(), Some("router"));
        assert_eq!(probed.actor.id, "alice");
        assert_eq!(param(probed, "fingerprint"), json!(ticket.fingerprint));
        let bootstrap = harness.audited("entware.ssh.bootstrap")?;
        let bootstrapped = bootstrap.first().ok_or("no bootstrap entry")?;
        assert_eq!(bootstrapped.outcome, "success");
        assert_eq!(
            param(bootstrapped, "fingerprint"),
            json!(ticket.fingerprint)
        );
    }
    Ok(())
}

/// Todo 9: a second probe and bootstrap replace kcc's line with the new key's: still one.
#[tokio::test]
async fn a_second_bootstrap_keeps_one_line() -> TestResult {
    let harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    let first = harness.kcc_lines()?;
    drop(harness.enrol().await?);
    let second = harness.kcc_lines()?;
    assert_eq!(second.len(), 1);
    assert_ne!(first, second, "the new key replaced the old line");
    assert_eq!(
        harness.record()?.ok_or("no record")?.state,
        EnrolmentState::Active
    );
    Ok(())
}

/// Todo 9: the typed password `keenetic` that signs in sets `default_password_in_use`,
/// with exactly one password attempt and one key offer, so no extra login computes it.
#[tokio::test]
async fn the_default_password_is_flagged_without_another_login() -> TestResult {
    let harness = Harness::default_start().await?;
    let enrolled = harness.enrol().await?;
    assert!(enrolled.default_password_in_use);
    let counters = harness.counters()?;
    assert_eq!((counters.password_attempts, counters.key_offers), (1, 1));
    let event = harness
        .audited("entware.ssh.bootstrap")?
        .pop()
        .ok_or("no bootstrap entry")?;
    assert_eq!(param(&event, "default_credentials_in_use"), json!(true));
    Ok(())
}

/// Todo 9: another password is not flagged, again with one password attempt and one key
/// offer.
#[tokio::test]
async fn another_password_is_not_flagged() -> TestResult {
    let password = format!("pw-{}", marker());
    let harness =
        Harness::start(Firmware::V5_1, Config::default().password(password.clone())).await?;
    let ticket = harness.probe().await?;
    let enrolled = harness.bootstrap_with(&ticket, &password).await??;
    assert!(!enrolled.default_password_in_use);
    let counters = harness.counters()?;
    assert_eq!((counters.password_attempts, counters.key_offers), (1, 1));
    Ok(())
}

/// Todo 9: the key, the pin and the router host are saved, Pending, before the router is
/// contacted: a connection dropped at the key append leaves them on disk and no line.
#[tokio::test]
async fn a_drop_at_the_append_leaves_the_pin_and_key_pending() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    let ssh = harness.ssh()?;
    ssh.set_fault(Some(Fault::KillAfter(ssh.counters().commands)));
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(matches!(outcome, Err(EntwareError::Ssh(_))), "{outcome:?}");
    let record = harness.record()?.ok_or("no record before contact")?;
    assert_eq!(record.state, EnrolmentState::Pending);
    assert_eq!(record.host_key.as_deref(), Some(ticket.host_key.as_str()));
    assert_eq!(record.router_host.as_deref(), Some("127.0.0.1"));
    assert!(harness.private_key()?.is_some(), "the key was saved first");
    assert_eq!(harness.kcc_lines()?.len(), 0);
    Ok(())
}

/// Todo 9: a connection dropped after the append (at the liveness check) leaves the
/// enrolment Pending with its pin and the line; a retry from Pending ends Active with one
/// line.
#[tokio::test]
async fn a_drop_after_the_append_stays_pending_and_a_retry_activates() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    let ssh = harness.ssh()?;
    ssh.set_fault(Some(Fault::KillAfter(
        ssh.counters().commands.saturating_add(1),
    )));
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(matches!(outcome, Err(EntwareError::Ssh(_))), "{outcome:?}");
    let record = harness.record()?.ok_or("no record")?;
    assert_eq!(record.state, EnrolmentState::Pending);
    assert_eq!(record.host_key.as_deref(), Some(ticket.host_key.as_str()));
    assert_eq!(harness.kcc_lines()?.len(), 1, "the append ran");
    ssh.set_fault(None);
    drop(harness.enrol().await?);
    assert_eq!(harness.kcc_lines()?.len(), 1);
    assert_eq!(
        harness.record()?.ok_or("no record")?.state,
        EnrolmentState::Active
    );
    Ok(())
}
