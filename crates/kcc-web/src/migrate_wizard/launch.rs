//! Starting an apply and recording its end: the engine's job, a follower copying the
//! job's progress into the migration's live view, and the settler.
//!
//! The settler keeps the applier the job hands back for the commit or the rollback,
//! records how the job ended, and frees the target when nothing is left to finish.

use alloc::sync::Arc;

use kcc_app::jobs::JobRunner;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::{Applier, ApplyError};
use tokio::sync::oneshot;

use super::{
    access::Visit,
    apply_request::{Prepared, Refused},
    live::Live,
    run::Run,
    service::{Session, Wizards},
    store::{Kept, Store, StoreError},
};
use crate::{WebState, authz::CurrentUser, page_kit::audit::Record as Audit};

/// Why an apply did not start.
pub(super) enum Failure {
    /// The preview says why, and the audit log records the outcome.
    Refused(MessageKey, &'static str),
    /// The migration's files could not be written.
    Broken(StoreError),
}

/// Starts the apply of `visit` with `jobs` and returns the job's id and the number of
/// commands it sends; the target is already reserved in `wizards`.
///
/// # Errors
///
/// Returns why the apply did not start; the caller frees the target.
// NOT cancel-safe: once the job started, it runs on without its record.
pub(super) async fn launch(
    visit: &mut Visit<'_>,
    state: &WebState,
    jobs: &Arc<JobRunner>,
    wizards: &Arc<Wizards>,
) -> Result<(String, usize), Failure> {
    let prepared = match Prepared::new(visit, state).await {
        Ok(found) => found,
        Err(Refused::Changed(plan)) => {
            visit.record_mut().preview_ready(plan);
            visit.save().map_err(Failure::Broken)?;
            return Err(Failure::Refused(keys::WEB_MIGRATE_APPLY_CHANGED, "changed"));
        }
        Err(Refused::Unreadable) => {
            return Err(Failure::Refused(
                keys::WEB_MIGRATE_PROBLEM_UNREACHABLE,
                "unreachable",
            ));
        }
        Err(Refused::Broken) => {
            return Err(Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"));
        }
    };
    let id = visit.record().id().to_owned();
    let (safety, commands) = (prepared.safety_seconds(), prepared.commands());
    let (request, texts, report, plan) = prepared.into_parts();
    let store = visit.services().store();
    store
        .keep(&id, Kept::Report, &report)
        .and_then(|()| store.keep(&id, Kept::Plan, &plan))
        .map_err(Failure::Broken)?;
    let now = state.unix_seconds();
    let live = Live::new(now, texts);
    let events = jobs.subscribe();
    let (job, done) = Applier::start(jobs, request)
        .await
        .map_err(|_error| Failure::Refused(keys::WEB_MIGRATE_APPLY_BUSY, "busy"))?;
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
    let target = visit.record().target().unwrap_or_default().to_owned();
    let settling = Settling {
        state: state.clone(),
        user: visit.services().user().clone(),
        wizards: Arc::clone(wizards),
        session,
        live,
        store,
        id,
        target,
    };
    drop(tokio::spawn(settle(settling, done)));
    visit
        .record_mut()
        .start_run(Run::new(job.clone(), now, safety));
    visit.save().map_err(Failure::Broken)?;
    Ok((job, commands))
}

/// What recording an apply's end needs.
struct Settling {
    /// Web services, for the time and the audit log.
    state: WebState,
    /// Who started it.
    user: CurrentUser,
    /// The wizards, to free the target.
    wizards: Arc<Wizards>,
    /// The migration's session, for its turn.
    session: Arc<Session>,
    /// The apply.
    live: Arc<Live>,
    /// The migrations directory.
    store: Store,
    /// The migration id.
    id: String,
    /// The target router.
    target: String,
}

/// Records how the apply ended once the job hands back its applier or its failure;
/// frees the target when nothing is left to commit or roll back.
// NOT cancel-safe: the record write and the audit append may be abandoned.
async fn settle(context: Settling, done: oneshot::Receiver<Result<Applier, ApplyError>>) {
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
    if let Ok(Some(mut record)) = context.store.load(&context.id)
        && let Some(run) = record.run_mut()
    {
        let outcome = match (&report, failure) {
            (Some(known), _) => Ok(known),
            (None, error) => Err(error.unwrap_or(ApplyError::Job)),
        };
        run.end(now, outcome);
        if let Err(error) = context.store.save(&record) {
            tracing::error!(%error, "migration end could not be recorded");
        }
    } else {
        tracing::error!(id = context.id, "migration record missing at its end");
    }
    if applier.is_none() {
        context.wizards.release(&context.target, &context.id);
    }
    let outcome = if verified { "verified" } else { "failed" };
    Audit::on_router("web.migrate_apply_end", &context.target, context.id)
        .append(&context.state, &context.user, outcome)
        .await;
    context.live.settle(applier, now).await;
    drop(turn);
}
