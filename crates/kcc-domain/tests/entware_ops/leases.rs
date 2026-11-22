//! The router write lease and the command timeouts: mutations hold the lease and run
//! under the mutation bound; reads take no lease and run under the read bound.

use alloc::sync::Arc;
use core::time::Duration;
use std::time::Instant;

use kcc_app::{
    accounts::{Clock, SystemClock},
    secrets::MasterKey,
    workflow::WorkflowError,
};
use kcc_domain::entware::ssh::{
    SshServices,
    error::EntwareError,
    ops::{self, ServiceVerb},
};
use kcc_ssh::{
    error::{Phase, SshError},
    transport::Timeouts,
};
use kcc_testkit::entware_ssh::Fault;
use tokio::time::timeout;

use crate::{
    harness::{LIMIT, ROUTER, actor},
    rig::{MUTATIONS, Op, READS, Rig},
    support::TestResult,
};

/// Todo 11: while another holder has the router write lease, every mutation is refused as
/// busy before any SSH command, and every read still runs.
#[tokio::test]
async fn a_held_lease_refuses_mutations_and_lets_reads_run() -> TestResult {
    let rig = Rig::start().await?;
    let _lease =
        rig.harness()
            .fixture()
            .workflow()
            .reserve(ROUTER, &actor("bob"), rig.harness().admin())?;
    for op in MUTATIONS {
        let before = rig.harness().counters()?;
        let outcome = rig.run(op).await?;
        assert!(
            matches!(
                outcome,
                Err(EntwareError::Workflow(WorkflowError::RouterBusy {
                    actor: _
                }))
            ),
            "{op:?}: {outcome:?}"
        );
        assert_eq!(rig.harness().counters()?, before, "{op:?}");
    }
    for op in READS {
        drop(rig.ok(op).await?);
    }
    Ok(())
}

/// Todo 11: a mutation holds the router write lease for its whole run.
///
/// While the fake holds the mutating command back, another actor's reservation is
/// refused as busy; once the command is answered and the mutation is done, the lease is
/// free again.
#[tokio::test]
async fn the_lease_is_held_while_the_mutating_command_runs() -> TestResult {
    let rig = Rig::start().await?;
    let (ssh, workflow) = (rig.harness().ssh()?, rig.harness().fixture().workflow());
    let admin = rig.harness().admin();
    let mutations = [
        (1, Op::Install("htop")),
        (2, Op::Action("S50nginx", ServiceVerb::Start)),
    ];
    for (held, op) in mutations {
        ssh.set_fault(Some(Fault::HoldMutations));
        let probe = async {
            timeout(LIMIT, ssh.held(held)).await??;
            let busy = workflow.reserve(ROUTER, &actor("bob"), admin).map(drop);
            ssh.set_fault(None);
            ssh.release().await;
            TestResult::Ok(busy)
        };
        let (outcome, probed) = tokio::join!(rig.run(op), probe);
        let busy = probed?;
        assert!(
            matches!(busy, Err(WorkflowError::RouterBusy { actor: _ })),
            "{op:?}: {busy:?}"
        );
        drop(outcome??);
        drop(workflow.reserve(ROUTER, &actor("bob"), admin)?);
    }
    Ok(())
}

/// Services over the rig's fixture with a 300 ms read bound and a 3 s mutation bound.
fn short_bounds(rig: &Rig) -> SshServices {
    let fixture = rig.harness().fixture();
    let mut timeouts = Timeouts::default();
    timeouts.connect = Duration::from_secs(5);
    timeouts.auth = Duration::from_secs(5);
    timeouts.read = Duration::from_millis(300);
    timeouts.mutation = Duration::from_secs(3);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    SshServices::new(
        Arc::clone(fixture.workflow()),
        fixture.registry(),
        fixture.audit().clone(),
        &MasterKey::from_bytes([9_u8; 32]),
        clock,
    )
    .with_timeouts(timeouts)
}

/// Todo 11: a hung read times out at the read bound, a hung mutation only at the
/// mutation bound (real time with injected bounds; the time is the behaviour).
#[tokio::test]
async fn reads_and_mutations_use_their_own_bound() -> TestResult {
    let rig = Rig::start().await?;
    let services = short_bounds(&rig);
    let (router, caller) = (rig.harness().context(), rig.harness().caller());
    rig.harness().ssh()?.set_fault(Some(Fault::Hang));
    let started = Instant::now();
    let read = timeout(LIMIT, ops::packages_list(&services, router, &caller)).await?;
    assert!(
        matches!(read, Err(EntwareError::Ssh(SshError::Timeout(Phase::Read)))),
        "{read:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3), "the read bound");
    let begun = Instant::now();
    let mutation = timeout(LIMIT, ops::update(&services, router, &caller)).await?;
    assert!(
        matches!(
            mutation,
            Err(EntwareError::Ssh(SshError::Timeout(Phase::Mutation)))
        ),
        "{mutation:?}"
    );
    assert!(
        begun.elapsed() >= Duration::from_secs(3),
        "the mutation bound"
    );
    Ok(())
}
