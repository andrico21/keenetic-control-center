//! Starting a run's apply and recording its end, with the migration wizard's machinery:
//! the engine's job, a follower copying the job's progress into the run's live view, and
//! the settler.
//!
//! The plan is built again from a fresh read of the target and refused when it is not the
//! plan the preview showed. The settler keeps the applier the job hands back for the
//! final choice, records how the job ended and the new WireGuard public keys, and frees
//! the target when nothing is left to finish.

use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;

use kcc_app::jobs::JobRunner;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::{Applier, ApplyError, ApplyReport, ApplyWarning};
use tokio::sync::oneshot;

use super::{
    access::Visit,
    lines::redacted,
    plan::Basis,
    record::{FILE, Record},
};
use crate::{
    WebState,
    authz::CurrentUser,
    brackets,
    page_kit::audit::Record as Audit,
    wizard::{
        analysis::Problem,
        expiry::{Watched, expire},
        flow::Flow as _,
        live::Live,
        run::Run,
        service::{Session, Wizards},
        store::{Store, StoreError},
    },
};

/// Why an apply did not start.
pub(super) enum Failure {
    /// The preview says why, and the audit log records the outcome.
    Refused(MessageKey, &'static str),
    /// The run's files could not be written.
    Broken(StoreError),
    /// The request has no server owner, so the apply could be cut off half-started.
    Unowned,
}

/// Starts the apply of `visit` with `jobs` and returns the job's id and the number of
/// commands it sends.
///
/// The target is read first, then reserved in `runs` and the request held, so a
/// request cut off before the job starts leaves the target free; once the job started,
/// the settler frees it.
///
/// # Errors
///
/// Returns why the apply did not start, with the target free again.
// NOT cancel-safe: once the job started, it runs on without its record.
pub(super) async fn launch(
    visit: &mut Visit<'_>,
    state: &WebState,
    jobs: &Arc<JobRunner>,
    runs: &Arc<Wizards<Record>>,
) -> Result<(String, usize), Failure> {
    let services = visit.services();
    visit.session().forget();
    let basis = Basis::of(visit).await.map_err(|problem| match problem {
        Problem::Unreachable => {
            Failure::Refused(keys::WEB_MIGRATE_PROBLEM_UNREACHABLE, "unreachable")
        }
        Problem::Source
        | Problem::FirmwareRequired
        | Problem::FirmwareOlder {
            source: _,
            target: _,
        }
        | Problem::Unsupported => Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"),
    })?;
    let request = basis
        .request(visit.record(), state, services)
        .map_err(|_refused| Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"))?;
    let plan_id = request.plan.plan_id.clone();
    if visit.record().preview() != Some(plan_id.as_str()) {
        visit.record_mut().preview_ready(plan_id);
        visit.save().map_err(Failure::Broken)?;
        return Err(Failure::Refused(keys::WEB_PRESETS_APPLY_CHANGED, "changed"));
    }
    let phases = &request.plan.phases;
    let texts = phases
        .additive
        .iter()
        .chain(&phases.prune)
        .chain(&phases.management)
        .map(|line| {
            let number = line.source_index.saturating_add(1);
            (line.source_index, (number, redacted(line.expose_command())))
        })
        .collect::<BTreeMap<_, _>>();
    let (safety, commands) = (request.options.safety_seconds, texts.len());
    let id = visit.record().id().to_owned();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let claim = runs
        .claim(&target, &id)
        .ok_or(Failure::Refused(keys::WEB_PRESETS_APPLY_BUSY, "busy"))?;
    if !brackets::hold() {
        return Err(Failure::Unowned);
    }
    let now = state.unix_seconds();
    let live = Live::new(now, texts);
    let events = jobs.subscribe();
    let (job, done) = Applier::start(jobs, request)
        .await
        .map_err(|_error| Failure::Refused(keys::WEB_PRESETS_APPLY_BUSY, "busy"))?;
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
        user: services.user().clone(),
        runs: Arc::clone(runs),
        session,
        live,
        store: services.store(),
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
    /// The runs, to free the target.
    runs: Arc<Wizards<Record>>,
    /// The run's session, for its turn.
    session: Arc<Session<Record>>,
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
/// Frees the target when nothing is left to keep, save or roll back, and otherwise when
/// the router's recovery window ends unfinished.
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
    let ended = match (&report, failure) {
        (Some(known), _) => Ok(known),
        (None, error) => Err(error.unwrap_or(ApplyError::Job)),
    };
    record_end(&context, now, ended);
    if applier.is_none() {
        context.runs.release(&context.target, &context.id);
    }
    let outcome = if verified { "verified" } else { "failed" };
    Audit::on_router("web.preset_apply_end", &context.target, context.id.clone())
        .append(&context.state, &context.user, outcome)
        .await;
    let window = applier.as_ref().map(Applier::recovery_left);
    context.live.settle(applier, now).await;
    drop(turn);
    if let Some(left) = window {
        watch(context, left);
    }
}

/// Ends the apply of `context` once the router's recovery window, `left` from now, ran
/// out unfinished.
fn watch(context: Settling, left: Duration) {
    let Settling {
        state,
        user,
        runs,
        session,
        live,
        store: _,
        id,
        target,
    } = context;
    let watched = Watched::new((state, user), (runs, session, live), (id, target));
    drop(tokio::spawn(expire(watched, left)));
}

/// Records in the run's record how its apply ended at `now`: the engine's report, or
/// the error it failed with before it made one.
fn record_end(context: &Settling, now: u64, outcome: Result<&ApplyReport, ApplyError>) {
    let Ok(Some(mut record)) = context.store.load_named::<Record>(&context.id, FILE) else {
        tracing::error!(id = context.id, "preset run record missing at its end");
        return;
    };
    if let Some(run) = record.run_mut() {
        run.end(now, outcome);
    }
    if let Ok(known) = outcome {
        let (keys, kept) = wireguard(known);
        record.set_keys(keys, kept);
    }
    if let Err(error) = context.store.save_named(&context.id, FILE, &record) {
        tracing::error!(%error, "preset run end could not be recorded");
    }
}

/// The new WireGuard public keys of `report`, and the interfaces whose captured key was
/// copied.
fn wireguard(report: &ApplyReport) -> (Vec<(String, String)>, Vec<String>) {
    let keys = report
        .wireguard_public_keys
        .iter()
        .map(|key| (key.interface.clone(), key.public_key.clone()))
        .collect();
    let kept = report
        .warnings
        .iter()
        .filter_map(|warning| {
            let ApplyWarning::WireGuardPrivateKeyKept { interface } = warning else {
                return None;
            };
            Some(interface.clone())
        })
        .collect();
    (keys, kept)
}
