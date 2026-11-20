//! Starting a prepared preset apply under the router's lease and ending it.

use kcc_app::workflow::WorkflowError;
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    configuration::{LastChangeState, read_last_change},
};
use kcc_migrate::apply::{Applier, ApplyError, ApplyRequest};
use tokio::sync::oneshot;

use crate::server_schedules::actions::{ActionDeps, ActionResult, failed};

/// Reserves the router's lease for `request`, starts the applier's job, and ends the
/// apply once its verdict is in; the result carries the job, which has ended by then.
///
/// A preparation that failed with the fail-safe timer possibly armed keeps the job, and
/// so the lease, until the timer has run out on the apply clock.
// NOT cancel-safe: dropped after the job started, the applier runs on detached, and a
// dropped applier leaves the router's fail-safe timer armed.
pub(super) async fn run(deps: &ActionDeps, mut request: ApplyRequest) -> ActionResult {
    match deps
        .workflow()
        .reserve(&request.target, &request.actor, &request.role)
    {
        Ok(reservation) => request.reservation = Some(reservation),
        Err(WorkflowError::RouterBusy { actor: _ }) => return ActionResult::Busy,
        Err(_error) => return failed("router"),
    }
    request.options.hold_armed_failure = true;
    let router = request.target.clone();
    let (id, done) = match Applier::start(deps.jobs(), request).await {
        Ok(started) => started,
        // The job runner refuses a second write job on the router as a job error.
        Err(ApplyError::Job) => return ActionResult::Busy,
        Err(_error) => return failed("job_start"),
    };
    deps.claim_job(&id);
    let result = conclude(deps, &router, done).await;
    deps.jobs().ended(&id).await;
    result.in_job(id)
}

/// Waits for the applier of `router` and ends its run.
///
/// A verified apply is kept unsaved, a failed one rolled back. When that finish fails,
/// the applier and its lease are kept until the fail-safe timer has run out on the apply
/// clock, and the router's `show last-change` tells how the run ended.
// NOT cancel-safe: dropped while it finishes or waits, the applier is dropped with the
// router's fail-safe timer possibly armed and the outcome lost.
async fn conclude(
    deps: &ActionDeps,
    router: &str,
    done: oneshot::Receiver<Result<Applier, ApplyError>>,
) -> ActionResult {
    let mut applier = match done.await {
        Ok(Ok(applier)) => applier,
        Ok(Err(error)) => return failed(unprepared(error)),
        Err(_lost) => return failed("job_lost"),
    };
    let verified = applier.report().failure.is_none();
    let finished = if verified {
        applier.keep_unsaved().await
    } else {
        applier.rollback().await
    };
    if finished.is_err() {
        deps.apply_clock().wait(applier.recovery_left()).await;
        let state = last_change(deps, router).await;
        drop(applier);
        return failed(recovered(state.as_ref()));
    }
    drop(applier);
    if !verified {
        return failed("preset_rolled_back");
    }
    let checksum = last_change(deps, router)
        .await
        .and_then(|state| state.checksum);
    ActionResult::Done {
        unsaved: true,
        checksum,
        job: None,
    }
}

/// The error code of an apply whose preparation failed.
///
/// No applier exists, so nothing is rolled back; the fail-safe timer may still be armed
/// when its arming or its cleanup went unconfirmed, and the job then keeps the lease until
/// the timer has run out.
pub(super) const fn unprepared(error: ApplyError) -> &'static str {
    if error.recovery_armed() {
        "preset_failed_armed"
    } else {
        "preset_failed"
    }
}

/// The error code of a run whose finish failed, from `show last-change` once the fail-safe
/// timer ran out: restored when the router answers that nothing is unsaved.
pub(super) fn recovered(state: Option<&LastChangeState>) -> &'static str {
    if state.and_then(|last| last.unsaved) == Some(false) {
        "preset_restored"
    } else {
        "preset_state_unknown"
    }
}

/// `show last-change` of `router` through its shared client, which signs in again when
/// the router restarted; `None` when the router does not answer.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
async fn last_change(deps: &ActionDeps, router: &str) -> Option<LastChangeState> {
    let info = deps.registry().poll_info(router).await.ok()?;
    let catalog = Catalog::for_router(&info).ok()?;
    let client = deps.registry().client(router).await.ok()?;
    read_last_change(&RouterCtx::new(client, catalog))
        .await
        .ok()
}
