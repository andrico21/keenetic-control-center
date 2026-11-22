//! Guards: the Destructive permission, MCP, `opkg chroot`, the router write lease and
//! the audit writer.

use std::fs;

use kcc_app::{
    audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditEvent},
    permissions::Role,
    workflow::WorkflowError,
};
use kcc_domain::entware::ssh::{
    Caller,
    enrol::{self, ProbeTicket},
    error::EntwareError,
};
use tokio::time::timeout;

use crate::{
    harness::{Harness, LIMIT, ROUTER, actor, operator},
    steps::{Call, LEASED_STEPS, LOCAL_STEPS, SSH_STEPS},
    support::TestResult,
};

/// An enrolled harness and a fresh, valid probe ticket.
// NOT cancel-safe: a dropped enrolment leaves the record pending.
async fn enrolled() -> TestResult<(Harness, ProbeTicket)> {
    let harness = Harness::default_start().await?;
    drop(harness.enrol().await?);
    let ticket = harness.probe().await?;
    Ok((harness, ticket))
}

/// Todo 9: a role without `Destructive` is refused by every step before any RCI request,
/// SSH connection or state change.
#[tokio::test]
async fn a_role_without_destructive_is_refused_before_anything() -> TestResult {
    let (harness, ticket) = enrolled().await?;
    let role = operator();
    let call = Call::new(
        harness.services(),
        harness.context(),
        Caller::new(ROUTER, harness.alice(), &role),
        &ticket,
    );
    let counters = harness.counters()?;
    let requests = harness.fixture().handle().request_count();
    let record = harness.record()?;
    for step in SSH_STEPS.into_iter().chain(LOCAL_STEPS) {
        let outcome = call.run(step).await?;
        assert!(
            matches!(outcome, Err(EntwareError::PermissionDenied)),
            "{step:?}: {outcome:?}"
        );
        assert_eq!(harness.counters()?, counters, "{step:?}");
        assert_eq!(
            harness.fixture().handle().request_count(),
            requests,
            "{step:?}"
        );
        assert_eq!(harness.record()?, record, "{step:?}");
    }
    Ok(())
}

/// Todo 9: probe, bootstrap, re-pin and revoke are refused to an MCP actor before any
/// request: the Entware password never travels through MCP.
#[tokio::test]
async fn mcp_is_refused_for_the_ssh_steps() -> TestResult {
    let (harness, ticket) = enrolled().await?;
    let mcp = Actor::new(ActorKind::Mcp, "alice".to_owned());
    let call = Call::new(
        harness.services(),
        harness.context(),
        Caller::new(ROUTER, &mcp, harness.admin()),
        &ticket,
    );
    let counters = harness.counters()?;
    let requests = harness.fixture().handle().request_count();
    for step in SSH_STEPS {
        let outcome = call.run(step).await?;
        assert!(
            matches!(outcome, Err(EntwareError::McpRefused)),
            "{step:?}: {outcome:?}"
        );
    }
    assert_eq!(harness.counters()?, counters);
    assert_eq!(harness.fixture().handle().request_count(), requests);
    Ok(())
}

/// Todo 9: with `opkg chroot` on, every SSH step is refused before any SSH connection,
/// while `set_port`, `set_enabled` and `disable` still work locally.
#[tokio::test]
async fn chroot_refuses_the_ssh_steps_before_any_connection() -> TestResult {
    let (harness, ticket) = enrolled().await?;
    assert!(harness.fixture().handle().configure("opkg chroot"));
    let call = Call::new(
        harness.services(),
        harness.context(),
        harness.caller(),
        &ticket,
    );
    let counters = harness.counters()?;
    for step in SSH_STEPS {
        let outcome = call.run(step).await?;
        assert!(
            matches!(outcome, Err(EntwareError::ChrootEnabled)),
            "{step:?}: {outcome:?}"
        );
        assert_eq!(harness.counters()?, counters, "{step:?}");
    }
    assert_eq!(harness.kcc_lines()?.len(), 1);
    for step in LOCAL_STEPS {
        call.run(step).await??;
    }
    assert_eq!(harness.record()?, None);
    Ok(())
}

/// Todo 9: while another holder has the router write lease, every mutating step is
/// refused as busy and changes nothing.
#[tokio::test]
async fn a_held_lease_refuses_every_mutating_step() -> TestResult {
    let (harness, ticket) = enrolled().await?;
    let admin: &Role = harness.admin();
    let _lease = harness
        .fixture()
        .workflow()
        .reserve(ROUTER, &actor("bob"), admin)?;
    let call = Call::new(
        harness.services(),
        harness.context(),
        harness.caller(),
        &ticket,
    );
    let counters = harness.counters()?;
    let record = harness.record()?;
    for step in LEASED_STEPS {
        let outcome = call.run(step).await?;
        assert!(
            matches!(
                outcome,
                Err(EntwareError::Workflow(WorkflowError::RouterBusy {
                    actor: _
                }))
            ),
            "{step:?}: {outcome:?}"
        );
        assert_eq!(harness.counters()?, counters, "{step:?}");
        assert_eq!(harness.record()?, record, "{step:?}");
    }
    assert_eq!(harness.kcc_lines()?.len(), 1);
    Ok(())
}

/// Todo 9: a probe with a dead audit writer is refused before any SSH connection or
/// ticket: an unaudited probe never runs.
#[tokio::test]
async fn a_dead_audit_writer_refuses_the_probe_before_any_connection() -> TestResult {
    let harness = Harness::default_start().await?;
    fs::write(
        harness.fixture().state_dir().join(AUDIT_FILE_NAME),
        b"not an entry\n",
    )?;
    let event = AuditEvent::new(1, actor("test"), "t".to_owned())
        .with_result("success".to_owned(), "audit-1".to_owned());
    if harness.fixture().audit().append(event).await.is_ok() || harness.fixture().audit().is_alive()
    {
        return Err("the audit writer survived a corrupt file".into());
    }
    let counters = harness.counters()?;
    let outcome = timeout(
        LIMIT,
        enrol::probe(harness.services(), harness.context(), &harness.caller()),
    )
    .await?;
    assert!(
        matches!(outcome, Err(EntwareError::Audit(_))),
        "{outcome:?}"
    );
    assert_eq!(harness.counters()?, counters);
    Ok(())
}
