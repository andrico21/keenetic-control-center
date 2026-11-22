//! Guards every operation runs before it connects: the Destructive permission, the
//! enrolment, SSH enabled, the router host, `opkg chroot` and the host key pin.

use std::fs;

use kcc_app::{
    audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditEvent},
    entware_ssh::state::EnrolmentState,
    workflow::WorkflowError,
};
use kcc_domain::entware::ssh::{Caller, enrol, error::EntwareError};
use kcc_ssh::error::SshError;

use crate::{
    harness::{ROUTER, actor, operator, param},
    rig::{MUTATIONS, Op, READS, Rig},
    support::TestResult,
};

/// Every operation.
fn every_op() -> impl Iterator<Item = Op> {
    READS.into_iter().chain(MUTATIONS)
}

/// Runs every operation as the administrator and requires `refused` for each, with no
/// SSH connection and no command.
// NOT cancel-safe: a dropped mutation may have changed the fake.
async fn refuses_all<F>(rig: &Rig, refused: F) -> TestResult
where
    F: Fn(&EntwareError) -> bool,
{
    let before = rig.harness().counters()?;
    for op in every_op() {
        let outcome = rig.run(op).await?;
        let error = outcome.err().ok_or_else(|| format!("{op:?} ran"))?;
        assert!(refused(&error), "{op:?}: {error:?}");
        assert_eq!(rig.harness().counters()?, before, "{op:?}");
    }
    Ok(())
}

/// Todo 11: a role without `Destructive` is refused by every operation before any router
/// request or SSH connection (D-SSHPERM: reads included).
#[tokio::test]
async fn every_operation_needs_destructive() -> TestResult {
    let rig = Rig::start().await?;
    let role = operator();
    let caller = Caller::new(ROUTER, rig.harness().alice(), &role);
    let (counters, requests) = (
        rig.harness().counters()?,
        rig.harness().fixture().handle().request_count(),
    );
    for op in every_op() {
        let outcome = rig.run_as(op, &caller).await?;
        assert!(
            matches!(outcome, Err(EntwareError::PermissionDenied)),
            "{op:?}: {outcome:?}"
        );
    }
    assert_eq!(rig.harness().counters()?, counters);
    assert_eq!(rig.harness().fixture().handle().request_count(), requests);
    let entries = rig.harness().audited("entware.ssh.install")?;
    assert_eq!(
        entries.first().map(|entry| entry.outcome.as_str()),
        Some("forbidden")
    );
    Ok(())
}

/// Todo 11: an MCP caller with `Destructive` runs the operations (the MCP toolset gates
/// them with `allow_destructive` and `confirm`); only enrolment is refused over MCP.
#[tokio::test]
async fn an_mcp_caller_runs_the_operations() -> TestResult {
    let rig = Rig::start().await?;
    let mcp = Actor::new(ActorKind::Mcp, "agent".to_owned());
    let caller = Caller::new(ROUTER, &mcp, rig.harness().admin());
    drop(rig.run_as(Op::List, &caller).await??);
    drop(rig.run_as(Op::Install("htop"), &caller).await??);
    let entries = rig.harness().audited("entware.ssh.install")?;
    let entry = entries.first().ok_or("no install entry")?;
    assert_eq!(
        (entry.actor.kind, entry.outcome.as_str()),
        (ActorKind::Mcp, "success")
    );
    Ok(())
}

/// Todo 11: a router whose enrolment is Pending, or that has no record, is refused.
#[tokio::test]
async fn an_unenrolled_router_is_refused() -> TestResult {
    let rig = Rig::start().await?;
    let pending = rig.harness().store()?;
    let mut record = pending.load(ROUTER)?.ok_or("no record")?;
    record.state = EnrolmentState::Pending;
    pending.save(ROUTER, &record)?;
    refuses_all(&rig, |error| matches!(error, EntwareError::NotEnrolled)).await?;
    let disabled = enrol::disable(rig.harness().services(), &rig.harness().caller()).await?;
    assert!(disabled.entware_key_still_authorized);
    refuses_all(&rig, |error| matches!(error, EntwareError::NotEnrolled)).await
}

/// Todo 11: an Active enrolment with SSH management switched off is refused.
#[tokio::test]
async fn ssh_switched_off_is_refused() -> TestResult {
    let rig = Rig::start().await?;
    drop(enrol::set_enabled(rig.harness().services(), &rig.harness().caller(), false).await?);
    refuses_all(&rig, |error| matches!(error, EntwareError::SshDisabled)).await
}

/// Todo 11: with `opkg chroot` on, every operation is refused before any connection.
#[tokio::test]
async fn chroot_on_is_refused() -> TestResult {
    let rig = Rig::start().await?;
    assert!(rig.harness().fixture().handle().configure("opkg chroot"));
    refuses_all(&rig, |error| matches!(error, EntwareError::ChrootEnabled)).await
}

/// Todo 11: through a router URL with another host every operation is refused before any
/// connection, and the pin is cleared.
#[tokio::test]
async fn a_changed_router_host_is_refused() -> TestResult {
    let rig = Rig::start().await?;
    let moved = rig.harness().fixture().context_via("router.example")?;
    for op in every_op() {
        let before = rig.harness().counters()?;
        let outcome = rig.run_via(op, &moved).await?;
        assert!(
            matches!(outcome, Err(EntwareError::RouterHostChanged)),
            "{op:?}: {outcome:?}"
        );
        assert_eq!(rig.harness().counters()?, before, "{op:?}");
        let record = rig.harness().record()?.ok_or("no record")?;
        assert_eq!(record.host_key, None, "{op:?}");
        drop(rig.harness().enrol().await?);
    }
    Ok(())
}

/// Todo 11: a changed host key refuses every operation before authentication and any
/// command, and is audited as `entware.ssh.hostkey_mismatch` naming the operation.
#[tokio::test]
async fn a_changed_host_key_is_refused_and_audited() -> TestResult {
    let rig = Rig::start().await?;
    drop(rig.harness().ssh()?.replace_host_key());
    for op in every_op() {
        let before = rig.harness().counters()?;
        let outcome = rig.run(op).await?;
        assert!(
            matches!(
                outcome,
                Err(EntwareError::Ssh(SshError::HostKeyMismatch {
                    expected: _,
                    actual: _
                }))
            ),
            "{op:?}: {outcome:?}"
        );
        let after = rig.harness().counters()?;
        assert_eq!(
            (after.auth_attempts, after.commands),
            (before.auth_attempts, before.commands),
            "{op:?}"
        );
    }
    let mismatches = rig.harness().audited("entware.ssh.hostkey_mismatch")?;
    assert_eq!(mismatches.len(), every_op().count());
    assert!(
        mismatches
            .iter()
            .any(|entry| param(entry, "operation") == "entware.ssh.install")
    );
    let entries = rig.harness().audited("entware.ssh.install")?;
    let entry = entries.first().ok_or("no install entry")?;
    assert_eq!(
        (entry.outcome.as_str(), param(entry, "reason")),
        ("refused", "hostkey_mismatch".into())
    );
    Ok(())
}

/// Todo 11: with a dead audit writer every operation, reads included, is refused before
/// any connection: an unaudited operation never runs.
#[tokio::test]
async fn a_dead_audit_writer_refuses_every_operation() -> TestResult {
    let rig = Rig::start().await?;
    let fixture = rig.harness().fixture();
    fs::write(fixture.state_dir().join(AUDIT_FILE_NAME), b"not an entry\n")?;
    let event = AuditEvent::new(1, actor("test"), "t".to_owned())
        .with_result("success".to_owned(), "audit-1".to_owned());
    if fixture.audit().append(event).await.is_ok() || fixture.audit().is_alive() {
        return Err("the audit writer survived a corrupt file".into());
    }
    refuses_all(&rig, |error| {
        matches!(
            error,
            EntwareError::Audit(_) | EntwareError::Workflow(WorkflowError::Audit(_))
        )
    })
    .await
}
