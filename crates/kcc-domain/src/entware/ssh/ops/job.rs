//! Entware mutations run as write jobs of the router.

use alloc::sync::Arc;

use kcc_app::{
    audit::Actor,
    jobs::{JobContext, JobProgress, JobRunner, JobTarget},
    permissions::Role,
};
use kcc_ssh::grammar::{PackageName, ServiceName};
use serde_json::{Value, json};

use super::{ActionExit, PackageChange, ServiceOutcome, ServiceVerb};
use crate::{
    RouterCtx,
    entware::ssh::{Caller, SshServices, error::EntwareError, preflight, report::Action},
};

/// A mutation run as a write job.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mutation {
    /// [`super::update`].
    Update,
    /// [`super::install`].
    Install(PackageName),
    /// [`super::remove`].
    Remove(PackageName),
    /// [`super::upgrade`].
    Upgrade(PackageName),
    /// [`super::service_action`].
    Service(ServiceName, ServiceVerb),
}

/// Why a cancelled mutation job ended: the text of its final record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Cancelled {
    /// The job was cancelled before its command was sent: nothing changed.
    #[error("Entware command cancelled before it was sent; nothing was changed")]
    BeforeSend,
    /// The cancellation arrived after the command was sent: the command ran to its end.
    #[error(
        "cancellation arrived after the Entware command was sent: the command ran to its end on the router; read the package or service state back"
    )]
    AfterSend,
}

/// Who runs a mutation job on which router, owned by the job.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Request {
    /// The router context.
    pub router: RouterCtx,
    /// The router id.
    pub router_id: String,
    /// The audited principal.
    pub actor: Actor,
    /// The principal's role.
    pub role: Role,
}

impl Request {
    /// `actor` with `role` on the router `router_id` reached through `router`.
    #[inline]
    #[must_use]
    pub const fn new(router: RouterCtx, router_id: String, actor: Actor, role: Role) -> Self {
        Self {
            router,
            router_id,
            actor,
            role,
        }
    }
}

/// Starts `mutation` as a write job of the router and returns its id.
///
/// The job kind is the operation's audit action (`entware.ssh.install`, ...). The job
/// ends with the read-back as structured progress (a [`super::PackageChange`] or
/// [`super::ServiceOutcome`] as JSON).
///
/// # Errors
/// [`EntwareError::PermissionDenied`] before the job starts, or the job runner's refusal
/// ([`EntwareError::Job`], e.g. another write job on the router). The operation's own
/// failures end the job as failed with the error text.
// NOT cancel-safe: once spawned, the job runs on without its id reaching the caller.
#[inline]
pub async fn start(
    jobs: &Arc<JobRunner>,
    services: Arc<SshServices>,
    request: Request,
    mutation: Mutation,
) -> Result<String, EntwareError> {
    preflight::authorize(&Caller::new(
        &request.router_id,
        &request.actor,
        &request.role,
    ))?;
    let kind = audited(&mutation).name().to_owned();
    let target = JobTarget::Write(request.router_id.clone());
    Ok(jobs
        .start(kind, target, move |context| {
            run(services, request, mutation, context)
        })
        .await?)
}

/// The audited operation of `mutation`, whose name is the job kind.
const fn audited(mutation: &Mutation) -> Action {
    match mutation {
        Mutation::Update => Action::Update,
        Mutation::Install(_) => Action::Install,
        Mutation::Remove(_) => Action::Remove,
        Mutation::Upgrade(_) => Action::Upgrade,
        Mutation::Service(_, verb) => verb.audited(),
    }
}

/// Runs `mutation` for `request`; on success the read-back is the job's last structured
/// progress, on failure the error text (which carries no output) is the job's message.
///
/// A job cancelled before it starts sends nothing ([`Cancelled::BeforeSend`]); a
/// cancellation that arrives later lets the command run to its end, and a successful job
/// then ends with its read-back and [`Cancelled::AfterSend`].
///
/// # Errors
/// The operation's error text, or the [`Cancelled`] text.
// NOT cancel-safe: dropped while a command runs, the router may finish the mutation.
async fn run(
    services: Arc<SshServices>,
    request: Request,
    mutation: Mutation,
    context: JobContext,
) -> Result<(), String> {
    if context.cancellation().is_cancelled() {
        return Err(Cancelled::BeforeSend.to_string());
    }
    let caller = Caller::new(&request.router_id, &request.actor, &request.role);
    let (shared, router) = (services.as_ref(), &request.router);
    let detail = match mutation {
        Mutation::Update => super::update(shared, router, &caller).await.map(|()| None),
        Mutation::Install(package) => super::install(shared, router, &caller, package)
            .await
            .map(|change| Some(change_value(&change))),
        Mutation::Remove(package) => super::remove(shared, router, &caller, package)
            .await
            .map(|change| Some(change_value(&change))),
        Mutation::Upgrade(package) => super::upgrade(shared, router, &caller, package)
            .await
            .map(|change| Some(change_value(&change))),
        Mutation::Service(service, verb) => {
            super::service_action(shared, router, &caller, service, verb)
                .await
                .map(|outcome| Some(outcome_value(&outcome)))
        }
    }
    .map_err(|error: EntwareError| error.to_string())?;
    if let Some(value) = detail {
        context.structured_progress(JobProgress::Structured(value));
    }
    context.progress(100);
    if context.cancellation().is_cancelled() {
        return Err(Cancelled::AfterSend.to_string());
    }
    Ok(())
}

/// A package change as JSON.
fn change_value(change: &PackageChange) -> Value {
    json!({
        "package": change.package.as_str(),
        "before": change.before,
        "after": change.after,
    })
}

/// A service outcome as JSON.
fn outcome_value(outcome: &ServiceOutcome) -> Value {
    let state = super::names::state_word(outcome.state);
    let exit = match outcome.exit {
        ActionExit::Done => json!("done"),
        ActionExit::AlreadyStopped => json!("already_stopped"),
        ActionExit::Other(code) => json!({ "other": code }),
    };
    json!({
        "service": outcome.service.as_str(),
        "state": state,
        "exit": exit,
    })
}
