//! Host keys: a swapped key, re-pinning and a changed router host.

use kcc_app::entware_ssh::state::EnrolmentState;
use kcc_domain::entware::ssh::error::EntwareError;
use kcc_ssh::{error::SshError, keys::HostKeyPin};
use kcc_testkit::entware_ssh::DEFAULT_PASSWORD;
use serde_json::json;

use crate::{
    harness::{Harness, param},
    steps::{Call, SSH_STEPS},
    support::TestResult,
};

/// The fingerprint of the SSH fake's current host key.
fn presented(harness: &Harness) -> TestResult<String> {
    Ok(HostKeyPin::from_openssh(&harness.ssh()?.host_key().to_openssh()?)?.fingerprint())
}

/// Todo 9: a host key swapped between probe and bootstrap is refused with
/// `HostKeyMismatch` before any password attempt, and audited as
/// `entware.ssh.hostkey_mismatch` with both public fingerprints.
#[tokio::test]
async fn a_host_key_swapped_after_the_probe_is_refused_before_authentication() -> TestResult {
    let harness = Harness::default_start().await?;
    let ticket = harness.probe().await?;
    drop(harness.ssh()?.replace_host_key());
    let actual = presented(&harness)?;
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(
        matches!(
            &outcome,
            Err(EntwareError::Ssh(SshError::HostKeyMismatch { expected, actual: shown }))
                if *expected == ticket.fingerprint && *shown == actual
        ),
        "{outcome:?}"
    );
    assert_eq!(harness.counters()?.auth_attempts, 0);
    let entry = harness
        .audited("entware.ssh.hostkey_mismatch")?
        .pop()
        .ok_or("no mismatch entry")?;
    assert_eq!(entry.router.as_deref(), Some("router"));
    assert_eq!(entry.actor.id, "alice");
    assert_eq!(entry.outcome, "refused");
    assert_eq!(param(&entry, "expected"), json!(ticket.fingerprint));
    assert_eq!(param(&entry, "actual"), json!(actual));
    let record = harness.record()?.ok_or("no record")?;
    assert_eq!(record.state, EnrolmentState::Pending);
    assert_eq!(record.host_key.as_deref(), Some(ticket.host_key.as_str()));
    Ok(())
}

/// Todo 9: once a host key is pinned, a bootstrap with another key is refused before any
/// password attempt; the admin must re-pin.
#[tokio::test]
async fn bootstrap_of_a_changed_host_key_requires_a_repin() -> TestResult {
    let harness = Harness::default_start().await?;
    let enrolled = harness.enrol().await?;
    drop(harness.ssh()?.replace_host_key());
    let ticket = harness.probe().await?;
    let before = harness.counters()?.auth_attempts;
    let outcome = harness.bootstrap_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(
        matches!(outcome, Err(EntwareError::RepinRequired)),
        "{outcome:?}"
    );
    assert_eq!(harness.counters()?.auth_attempts, before);
    let record = harness.record()?.ok_or("no record")?;
    assert_eq!(record.state, EnrolmentState::Active);
    assert_eq!(record.fingerprint, Some(enrolled.fingerprint));
    Ok(())
}

/// Todo 9: a re-pin of a changed host key pins the new key, replaces kcc's line and ends
/// Active; the audit names the previous and the new fingerprint.
#[tokio::test]
async fn repin_pins_the_changed_host_key() -> TestResult {
    let harness = Harness::default_start().await?;
    let first = harness.enrol().await?;
    drop(harness.ssh()?.replace_host_key());
    let ticket = harness.probe().await?;
    let repinned = harness.repin_with(&ticket, DEFAULT_PASSWORD).await??;
    assert_eq!(repinned.fingerprint, presented(&harness)?);
    let record = harness.record()?.ok_or("no record")?;
    assert_eq!(record.state, EnrolmentState::Active);
    assert_eq!(record.host_key.as_deref(), Some(ticket.host_key.as_str()));
    assert_eq!(harness.kcc_lines()?.len(), 1);
    let event = harness
        .audited("entware.ssh.repin")?
        .pop()
        .ok_or("no repin entry")?;
    assert_eq!(event.outcome, "success");
    assert_eq!(
        param(&event, "previous_fingerprint"),
        json!(first.fingerprint)
    );
    assert_eq!(param(&event, "fingerprint"), json!(ticket.fingerprint));
    Ok(())
}

/// Todo 9: a re-pin of the pinned key itself is refused before any password attempt, and
/// a re-pin of a router with nothing pinned is refused too.
#[tokio::test]
async fn repin_of_an_unchanged_or_missing_pin_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let fresh = harness.probe().await?;
    let missing = harness.repin_with(&fresh, DEFAULT_PASSWORD).await?;
    assert!(
        matches!(missing, Err(EntwareError::NotEnrolled)),
        "{missing:?}"
    );
    drop(harness.enrol().await?);
    let ticket = harness.probe().await?;
    let before = harness.counters()?.auth_attempts;
    let unchanged = harness.repin_with(&ticket, DEFAULT_PASSWORD).await?;
    assert!(
        matches!(unchanged, Err(EntwareError::HostKeyUnchanged)),
        "{unchanged:?}"
    );
    assert_eq!(harness.counters()?.auth_attempts, before);
    Ok(())
}

/// Todo 9: a revoke against a swapped host key is refused before authentication, keeps
/// the record and the line, and is audited as a host key mismatch.
#[tokio::test]
async fn revoke_against_a_swapped_host_key_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    drop(harness.ssh()?.replace_host_key());
    let before = harness.counters()?.auth_attempts;
    let outcome = harness.revoke_via(harness.context()).await?;
    assert!(
        matches!(
            outcome,
            Err(EntwareError::RevokeFailed(SshError::HostKeyMismatch {
                expected: _,
                actual: _
            }))
        ),
        "{outcome:?}"
    );
    assert_eq!(harness.counters()?.auth_attempts, before);
    assert_eq!(harness.kcc_lines()?.len(), 1);
    assert_eq!(
        harness.record()?.ok_or("no record")?.state,
        EnrolmentState::Active
    );
    assert_eq!(harness.audited("entware.ssh.hostkey_mismatch")?.len(), 1);
    Ok(())
}

/// Todo 9: a changed router URL host refuses each SSH step and clears the pin.
///
/// Each step is refused before any connection, the record turns Pending without pin or
/// router host; a new probe and bootstrap enrol the router again.
#[tokio::test]
async fn a_changed_router_host_resets_the_enrolment() -> TestResult {
    let harness = Harness::default_start().await?;
    let moved = harness.fixture().context_via("router.example")?;
    for step in SSH_STEPS {
        drop(harness.enrol().await?);
        let ticket = harness.probe().await?;
        let before = harness.counters()?;
        let call = Call::new(harness.services(), &moved, harness.caller(), &ticket);
        let outcome = call.run(step).await?;
        assert!(
            matches!(outcome, Err(EntwareError::RouterHostChanged)),
            "{step:?}: {outcome:?}"
        );
        assert_eq!(harness.counters()?, before, "{step:?}");
        let record = harness.record()?.ok_or("no record")?;
        assert_eq!(record.state, EnrolmentState::Pending, "{step:?}");
        assert_eq!(
            (record.host_key, record.fingerprint, record.router_host),
            (None, None, None),
            "{step:?}"
        );
    }
    drop(harness.enrol().await?);
    assert_eq!(
        harness.record()?.ok_or("no record")?.state,
        EnrolmentState::Active
    );
    Ok(())
}
