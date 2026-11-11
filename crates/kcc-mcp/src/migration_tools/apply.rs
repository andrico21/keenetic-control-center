//! `kcc_migration_apply`: starts the engine's apply job and follows it to its verdict.

use alloc::sync::Arc;
use core::{
    future::{Future as _, poll_fn},
    pin::Pin,
    task::Poll,
};

use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::{JobEvent, JobProgress},
    permissions::Permission,
};
use kcc_migrate::apply::{Applier, ApplyError, ApplyRequest, ApplySource};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, oneshot};

use crate::{
    KccMcp, McpFailure, RouterId, authorize_routers,
    support::{
        route::{Progress, parse},
        validate::valid_job_id,
    },
};

/// Arguments of `kcc_migration_apply`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyInput {
    /// Target router profile id.
    host: String,
    /// Plan id returned by `kcc_migration_plan`.
    plan_id: String,
    /// Required: confirms applying the reviewed plan.
    #[serde(default)]
    confirm: bool,
    /// Acknowledges a target whose firmware support is documentation-based (audited).
    #[serde(default)]
    ack_documentation_tier: bool,
}

/// Maps a value-free engine failure.
pub(crate) const fn map_apply(error: ApplyError) -> McpFailure {
    match error {
        ApplyError::DisarmFailed => McpFailure::ManagementAppliedFailSafeArmed,
        ApplyError::UnverifiedFirmwareTier => McpFailure::UnverifiedFirmwareTier,
        ApplyError::Source | ApplyError::Unreachable => McpFailure::RouterUnreachable,
        ApplyError::RolledBackByRouter => McpFailure::RouterRejected,
        ApplyError::Drift
        | ApplyError::ReplanRequired
        | ApplyError::Workflow
        | ApplyError::Cancelled
        | ApplyError::Stopped => McpFailure::Conflict,
        ApplyError::JobStart => McpFailure::JobUnavailable,
        ApplyError::Job => McpFailure::Internal,
        ApplyError::SameRouter
        | ApplyError::Firmware
        | ApplyError::AgreementRequired
        | ApplyError::PasswordRequired
        | ApplyError::Validation
        | ApplyError::Verification
        | ApplyError::HardwareMismatch
        | _ => McpFailure::ValidationFailed,
    }
}

/// Validates the arguments, then returns the migration's routers and a copy of its plan.
async fn reviewed(
    server: &KccMcp,
    input: &ApplyInput,
) -> Result<([RouterId; 2], kcc_migrate::planner::MigrationPlan), McpFailure> {
    valid_job_id(&input.plan_id)?;
    let (identity, host) = server.authorize_host(Permission::Migrate, input.host.clone())?;
    authorize_routers(
        &identity,
        kcc_domain::configuration::SafetyNet::CONTROL_PERMISSION,
        core::slice::from_ref(&host),
    )?;
    let entries = server.migrations.lock().await;
    let migration = entries
        .get(&input.plan_id)
        .ok_or(McpFailure::InvalidArguments)?;
    let (routers, plan, applied) = (
        migration.routers_for(&identity)?,
        migration.plan().clone(),
        migration.applied(),
    );
    drop(entries);
    let [_source, target] = &routers;
    if target.as_str() != input.host {
        return Err(McpFailure::InvalidArguments);
    }
    if applied {
        return Err(McpFailure::Conflict);
    }
    authorize_routers(&identity, Permission::Migrate, &routers)?;
    if !input.confirm {
        return Err(McpFailure::ConfirmRequired);
    }
    Ok((routers, plan))
}

/// Applies a reviewed plan; the call returns once the apply phase ends, before commit.
pub(crate) async fn apply(
    server: &KccMcp,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let input: ApplyInput = parse(arguments)?;
    let ([source, target], plan) = reviewed(server, &input).await?;
    let identity = server.identity()?;
    let audit = server.audit.clone().ok_or(McpFailure::Internal)?;
    let client = server
        .registry
        .client(source.as_str())
        .await
        .map_err(|_error| McpFailure::RouterUnreachable)?;
    let mut request = ApplyRequest::new(
        Arc::clone(&server.workflow),
        audit,
        Actor::new(ActorKind::Mcp, identity.name.clone()),
        identity.role.clone(),
        target.as_str().to_owned(),
        plan,
        ApplySource::LiveRouter {
            id: source.as_str().to_owned(),
            client,
        },
    );
    request.options.ack_documentation_tier = input.ack_documentation_tier;
    let mut events = server.jobs.subscribe();
    let (job, done) = Applier::start(&server.jobs, request)
        .await
        .map_err(map_apply)?;
    let applier = follow(&job, &mut events, done, progress.as_ref())
        .await
        .map_err(map_apply)?;
    let mut entries = server.migrations.lock().await;
    let migration = entries
        .get_mut(&input.plan_id)
        .ok_or(McpFailure::Internal)?;
    migration.record_apply(job.clone(), applier);
    let mut value = migration.summary();
    drop(entries);
    if let Value::Object(summary) = &mut value {
        drop(summary.insert("job_id".to_owned(), json!(job)));
    }
    Ok(value)
}

/// Forwards the job's events as progress notifications until the apply phase ends;
/// buffered events are forwarded before the verdict is taken.
pub(crate) async fn follow(
    job: &str,
    events: &mut broadcast::Receiver<JobEvent>,
    mut done: oneshot::Receiver<Result<Applier, ApplyError>>,
    progress: Option<&Progress>,
) -> Result<Applier, ApplyError> {
    let mut sent = 0_u32;
    loop {
        let mut next = Box::pin(events.recv());
        let step = poll_fn(|context| {
            if let Poll::Ready(event) = next.as_mut().poll(context) {
                return Poll::Ready(Step::Event(event));
            }
            Pin::new(&mut done)
                .poll(context)
                .map(|result| Step::Done(Box::new(result)))
        })
        .await;
        drop(next);
        match step {
            Step::Done(result) => return (*result).map_err(|_error| ApplyError::Job)?,
            Step::Event(Ok(event)) if event.id == job => {
                if let Some(progress) = progress {
                    sent = sent.saturating_add(1);
                    progress.notify(sent, describe(&event)).await;
                }
            }
            Step::Event(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Step::Event(Err(broadcast::error::RecvError::Closed)) => {
                return done.await.map_err(|_error| ApplyError::Job)?;
            }
        }
    }
}

/// Whichever of the job's verdict and its next event arrived first.
enum Step {
    /// The apply phase ended.
    Done(Box<Result<Result<Applier, ApplyError>, oneshot::error::RecvError>>),
    /// A job event arrived.
    Event(Result<JobEvent, broadcast::error::RecvError>),
}

/// A value-free progress message.
fn describe(event: &JobEvent) -> String {
    match &event.detail {
        Some(JobProgress::OutputLine(line)) => line.clone(),
        Some(JobProgress::Structured(_) | _) | None => format!("{}%", event.progress),
    }
}
