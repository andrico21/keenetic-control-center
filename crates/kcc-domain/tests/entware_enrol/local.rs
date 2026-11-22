//! Revoke, disable and the local settings.

use alloc::sync::Arc;
use core::str::FromStr as _;
use std::net::TcpListener;

use kcc_app::entware_ssh::{SshStateError, state::EnrolmentState};
use kcc_domain::{
    RouterCtx,
    entware::ssh::{enrol, error::EntwareError},
};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_ssh::error::SshError;
use secrecy::SecretString;
use serde_json::json;
use tokio::time::timeout;

use crate::{
    harness::{Harness, LIMIT, marker, param},
    support::TestResult,
};

/// Todo 9: revoke removes kcc's line over SSH, then the local record and key, and is
/// audited with the public fingerprint.
#[tokio::test]
async fn revoke_removes_the_line_and_the_local_state() -> TestResult {
    let harness = Harness::default_start().await?;
    let enrolled = harness.enrol().await?;
    harness.revoke_via(harness.context()).await??;
    assert_eq!(harness.kcc_lines()?.len(), 0);
    assert_eq!(harness.record()?, None);
    assert_eq!(harness.private_key()?, None);
    let event = harness
        .audited("entware.ssh.revoke")?
        .pop()
        .ok_or("no revoke entry")?;
    assert_eq!(event.outcome, "success");
    assert_eq!(param(&event, "fingerprint"), json!(enrolled.fingerprint));
    Ok(())
}

/// Todo 9: a revoke that cannot reach the router over SSH is refused, points at
/// `disable`, and keeps the record and the key.
#[tokio::test]
async fn revoke_of_an_unreachable_router_keeps_the_record() -> TestResult {
    let mut harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    harness.stop_ssh().await?;
    let outcome = harness.revoke_via(harness.context()).await?;
    assert!(
        matches!(
            &outcome,
            Err(error @ EntwareError::RevokeFailed(SshError::Connect))
                if error.to_string().contains("disable")
        ),
        "{outcome:?}"
    );
    assert_eq!(
        harness.record()?.ok_or("the record was wiped")?.state,
        EnrolmentState::Active
    );
    assert!(harness.private_key()?.is_some(), "the key was wiped");
    Ok(())
}

/// Todo 9: a revoke that cannot reach the router over RCI (the `opkg chroot` read fails)
/// is refused, points at `disable`, keeps the record and the key, and is audited as a
/// failed router read.
#[tokio::test]
async fn revoke_of_a_router_unreachable_over_rci_points_at_disable() -> TestResult {
    let harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let client = RciClient::connect_resolved(
        RouterUrl::from_str(&format!("http://127.0.0.1:{}", closed.port()))?,
        Credentials::new(
            "admin".to_owned(),
            SecretString::from(format!("x{}", marker())),
        ),
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true)),
        &[closed],
    )?;
    let unreachable = RouterCtx::new(Arc::new(client), harness.context().catalog.clone());
    let outcome = harness.revoke_via(&unreachable).await?;
    let refusal = outcome.as_ref().err().map(ToString::to_string);
    assert!(
        refusal.is_some_and(|text| text.contains("disable")),
        "{outcome:?}"
    );
    assert_eq!(
        harness.record()?.ok_or("the record was wiped")?.state,
        EnrolmentState::Active
    );
    assert!(harness.private_key()?.is_some(), "the key was wiped");
    let event = harness
        .audited("entware.ssh.revoke")?
        .pop()
        .ok_or("no revoke entry")?;
    assert_eq!(event.outcome, "failed");
    assert_eq!(param(&event, "error"), json!("router"));
    Ok(())
}

/// Todo 9: disable forgets the record and the key without contacting the router (no RCI
/// request, no SSH connection), reports that the key stays authorized there, and is
/// audited.
#[tokio::test]
async fn disable_forgets_locally_and_leaves_the_key_authorized() -> TestResult {
    let harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    let counters = harness.counters()?;
    let requests = harness.fixture().handle().request_count();
    let disabled = enrol::disable(harness.services(), &harness.caller()).await?;
    assert!(disabled.entware_key_still_authorized);
    assert_eq!(harness.record()?, None);
    assert_eq!(harness.private_key()?, None);
    assert_eq!(harness.kcc_lines()?.len(), 1, "the router keeps the line");
    assert_eq!(harness.counters()?, counters);
    assert_eq!(harness.fixture().handle().request_count(), requests);
    let event = harness
        .audited("entware.ssh.disable")?
        .pop()
        .ok_or("no disable entry")?;
    assert_eq!(event.outcome, "success");
    assert_eq!(param(&event, "entware_key_still_authorized"), json!(true));
    Ok(())
}

/// Todo 9: switching SSH management off keeps the pin and the Active state.
#[tokio::test]
async fn set_enabled_off_keeps_the_pin() -> TestResult {
    let harness = Harness::default_start().await?;
    let enrolled = harness.enrol().await?;
    let record = enrol::set_enabled(harness.services(), &harness.caller(), false).await?;
    assert!(!record.enabled);
    let stored = harness.record()?.ok_or("no record")?;
    assert!(!stored.enabled);
    assert_eq!(stored.state, EnrolmentState::Active);
    assert_eq!(stored.fingerprint, Some(enrolled.fingerprint));
    Ok(())
}

/// Todo 9: port 0 is refused and the stored port stays.
#[tokio::test]
async fn port_zero_is_refused() -> TestResult {
    let harness = Harness::default_start().await?;
    let port = harness.ssh_address()?.port();
    let outcome = harness.set_port(0).await;
    assert!(
        matches!(
            outcome,
            Err(EntwareError::State(SshStateError::InvalidPort))
        ),
        "{outcome:?}"
    );
    assert_eq!(harness.record()?.ok_or("no record")?.port, port);
    Ok(())
}

/// Todo 9: without a record the probe dials port 222.
#[tokio::test]
async fn a_probe_without_a_record_uses_port_222() -> TestResult {
    let harness = Harness::default_start().await?;
    let _disabled = enrol::disable(harness.services(), &harness.caller()).await?;
    let outcome = timeout(
        LIMIT,
        enrol::probe(harness.services(), harness.context(), &harness.caller()),
    )
    .await?;
    let event = harness
        .audited("entware.ssh.probe")?
        .pop()
        .ok_or("no probe entry")?;
    assert_eq!(param(&event, "port"), json!(222_u16), "{outcome:?}");
    Ok(())
}

/// Todo 9: with the router unreachable over RCI and SSH, `set_port`, `set_enabled` and
/// `disable` still work locally and send nothing.
#[tokio::test]
async fn an_unreachable_router_still_allows_the_local_steps() -> TestResult {
    let mut harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    harness.stop_ssh().await?;
    let _stall = harness.fixture().handle().stall();
    let requests = harness.fixture().handle().request_count();
    let services = harness.services();
    let caller = harness.caller();
    let ported = timeout(LIMIT, enrol::set_port(services, &caller, 2222)).await??;
    assert_eq!(ported.port, 2222);
    let switched = timeout(LIMIT, enrol::set_enabled(services, &caller, false)).await??;
    assert!(!switched.enabled);
    let disabled = timeout(LIMIT, enrol::disable(services, &caller)).await??;
    assert!(disabled.entware_key_still_authorized);
    assert_eq!(harness.record()?, None);
    assert_eq!(harness.fixture().handle().request_count(), requests);
    Ok(())
}
