//! Starting a run's apply and recording its end: the engine's job, a follower copying the
//! job's progress into the run's live view, and the settler.
//!
//! The settler keeps the applier the job hands back for the final choice, records how
//! the job ended (through [`Applying::record_end`]), and frees the target when nothing is
//! left to finish.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::jobs::JobRunner;
use kcc_migrate::apply::{Applier, ApplyError, ApplyReport};
use tokio::sync::oneshot;

use super::{
    applying::{Applying, Failure},
    expiry::{Watched, expire},
    live::Live,
    run::Run,
    service::{Session, Wizards},
    store::Store,
    visit::Visit,
};
use crate::{WebState, authz::CurrentUser, brackets, page_kit::audit::Record as Audit};

/// Starts the apply of `visit` with `jobs` and returns the job's id and the number of
/// commands it sends.
///
/// The plan is prepared first, then the target reserved in `wizards` and the request
/// held, so a request cut off before the job starts leaves the target free; once the job
/// started, the settler frees it.
///
/// # Errors
///
/// Returns why the apply did not start, with the target free again.
// NOT cancel-safe: once the job started, it runs on without its record.
pub(crate) async fn start<F>(
    visit: &mut Visit<'_, F>,
    state: &WebState,
    (jobs, wizards): (&Arc<JobRunner>, &Arc<Wizards<F>>),
) -> Result<(String, usize), Failure>
where
    F: Applying,
{
    let (request, texts) = F::prepare(visit, state).await?.into_parts();
    let (safety, commands) = (request.options.safety_seconds, texts.len());
    let id = visit.record().id().to_owned();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let claim = wizards
        .claim(&target, &id)
        .ok_or(Failure::Refused(F::BUSY, "busy"))?;
    if !brackets::hold() {
        return Err(Failure::Unowned);
    }
    let now = state.unix_seconds();
    let live = Live::new(now, texts);
    let events = jobs.subscribe();
    let (job, done) = Applier::start(jobs, request).await.map_err(|error| {
        if error == ApplyError::Job {
            Failure::Refused(F::BUSY, "busy")
        } else {
            Failure::NotStarted(error)
        }
    })?;
    claim.disarm();
    let session = visit.session();
    session.set_live(Some(Arc::clone(&live)));
    let follower = Arc::clone(&live);
    let clock = state.clone();
    let job_id = job.clone();
    drop(tokio::spawn(async move {
        follower
            .follow(events, &job_id, || clock.unix_seconds())
            .await;
    }));
    let settling = Settling {
        state: state.clone(),
        user: visit.services().user().clone(),
        wizards: Arc::clone(wizards),
        session,
        live,
        store: visit.services().store(),
        id,
        target,
    };
    drop(tokio::spawn(settle(settling, done)));
    visit
        .record_mut()
        .start_run(Run::new(job.clone(), now, safety));
    visit.save().await.map_err(Failure::Broken)?;
    Ok((job, commands))
}

/// What recording an apply's end needs.
struct Settling<F>
where
    F: Applying,
{
    /// Web services, for the time, the run's files and the audit log.
    state: WebState,
    /// Who started it.
    user: CurrentUser,
    /// The wizards, to free the target.
    wizards: Arc<Wizards<F>>,
    /// The run's session, for its turn.
    session: Arc<Session<F>>,
    /// The apply.
    live: Arc<Live>,
    /// The runs' directory.
    store: Store,
    /// The run id.
    id: String,
    /// The target router.
    target: String,
}

/// Records how the apply ended once the job hands back its applier or its failure.
///
/// Frees the target when nothing is left to finish, and otherwise when the router's
/// recovery window ends unfinished.
// NOT cancel-safe: the record write and the audit append may be abandoned.
async fn settle<F>(context: Settling<F>, done: oneshot::Receiver<Result<Applier, ApplyError>>)
where
    F: Applying,
{
    let handed = done.await;
    let turn = context.session.turn().await;
    let (applier, failure) = match handed {
        Ok(Ok(applier)) => (Some(applier), None),
        Ok(Err(error)) => (None, Some(error)),
        Err(_closed) => (None, Some(ApplyError::Job)),
    };
    let report = applier.as_ref().map(|found| found.report().clone());
    let verified = report.as_ref().is_some_and(|known| known.verified);
    let now = context.state.unix_seconds();
    let ended = match (&report, failure) {
        (Some(known), _) => Ok(known),
        (None, error) => Err(error.unwrap_or(ApplyError::Job)),
    };
    record_end(&context, now, ended).await;
    if applier.is_none() {
        context.wizards.release(&context.target, &context.id);
    }
    let outcome = if verified { "verified" } else { "failed" };
    Audit::on_router(F::APPLY_END_AUDIT, &context.target, context.id.clone())
        .append(&context.state, &context.user, outcome)
        .await;
    let window = applier.as_ref().map(Applier::recovery_left);
    context.live.settle(applier, now).await;
    drop(turn);
    if let Some(left) = window {
        watch(context, left);
    }
}

/// Records in the run's record how its apply ended at `now`.
// NOT cancel-safe: dropped, the record write still completes.
async fn record_end<F>(context: &Settling<F>, now: u64, outcome: Result<&ApplyReport, ApplyError>)
where
    F: Applying,
{
    let store = &context.store;
    let Ok(Some(mut record)) = store.load::<F>(&context.id).await else {
        tracing::error!(id = context.id, "run record missing at its apply's end");
        return;
    };
    record.record_end(now, outcome);
    if let Err(error) = store.save(&record).await {
        tracing::error!(%error, "apply end could not be recorded");
    }
}

/// Ends the apply of `context` once the router's recovery window, `left` from now, ran
/// out unfinished.
fn watch<F>(context: Settling<F>, left: Duration)
where
    F: Applying,
{
    let Settling {
        state,
        user,
        wizards,
        session,
        live,
        store: _,
        id,
        target,
    } = context;
    let watched = Watched::new((state, user), (wizards, session, live), (id, target));
    drop(tokio::spawn(expire(watched, left)));
}
