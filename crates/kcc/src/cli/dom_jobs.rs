//! Diagnostic jobs, the component commit and auto-update, and the fail-safe keep-alive.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    jobs::{JobEvent, JobProgress, JobRunner, JobStatus},
    permissions::Permission,
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_domain::{
    components::{self, CommitError, QueueAction},
    configuration::SafetyNet,
    diagnostics::{self, DiagnosticKind},
};
use kcc_i18n::keys;
use serde_json::{Map, Value, json};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::{
    args_dom_jobs::{ComponentsCommand, ConfigCommand, DiagnosticsCommand, ProbeArgs},
    args_domains_net::QueueChoice,
    change::{Gate, applied},
    context::{Ctx, Services},
    domains::Session,
    exit::{Detail, Exit, Failure, Outcome},
    persist,
    secret::confirm,
};

/// Runs a `config` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: save, commit, rollback and the keep-alive may complete before
// cancellation.
pub(crate) async fn config(ctx: &Ctx, command: ConfigCommand) -> Outcome {
    match command {
        ConfigCommand::State => persist::config_state(ctx).await,
        ConfigCommand::Save => persist::config_save(ctx).await,
        ConfigCommand::Failsafe { action, seconds } => {
            persist::failsafe(ctx, action, seconds).await
        }
        ConfigCommand::KeepAlive => keep_alive(ctx).await,
    }
}

/// Restarts the countdown of the router's armed fail-safe timer.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the keep-alive may reach the router before cancellation.
async fn keep_alive(ctx: &Ctx) -> Outcome {
    let session = Session::open(ctx, Permission::Destructive).await?;
    let gate = Gate::new(Risk::Write, Permission::Destructive, false)
        .reporting(keys::CLI_FAILSAFE_RUNNING);
    session
        .change(gate, async |changes, router| {
            Ok(applied(
                SafetyNet::keep_alive(changes, router, Permission::Destructive)
                    .await?
                    .unsaved,
            ))
        })
        .await
}

/// Runs a diagnostic job and waits for its lines.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the job keeps running in this process until it ends.
pub(crate) async fn diagnostics(ctx: &Ctx, command: DiagnosticsCommand) -> Outcome {
    let (kind, args) = match command {
        DiagnosticsCommand::Ping(args) => (DiagnosticKind::Ping, args),
        DiagnosticsCommand::Ping6(args) => (DiagnosticKind::Ping6, args),
        DiagnosticsCommand::Traceroute(args) => (DiagnosticKind::Traceroute, args),
        DiagnosticsCommand::Arping(args) => (DiagnosticKind::Arping, args),
        DiagnosticsCommand::Iperf3(args) => (DiagnosticKind::Iperf3, args),
    };
    let services = ctx.services().await?;
    let target = ctx.target(&services, &[Permission::Read]).await?;
    let validated = target
        .router()
        .catalog
        .validate(
            kind.catalog_path(),
            HttpMethod::Post,
            &probe_body(kind, &args),
        )
        .map_err(|issues| Failure::new(Exit::Validation, Detail::Issues(issues)))?;
    let jobs = runner(ctx, &services).await?;
    let events = jobs.subscribe();
    let job = diagnostics::start_job(
        &jobs,
        target.id().to_owned(),
        Arc::clone(&target.router().client),
        kind,
        validated.value().clone(),
    )
    .await
    .map_err(|error| Failure::text(Exit::Conflict, &error))?;
    report(ctx, &job, follow(&job, events).await)
}

/// The catalog arguments of a probe: the target and the options given.
fn probe_body(kind: DiagnosticKind, args: &ProbeArgs) -> Value {
    let target = if matches!(kind, DiagnosticKind::Arping) {
        "address"
    } else {
        "host"
    };
    let mut body = Map::new();
    drop(body.insert(target.to_owned(), Value::from(args.target.as_str())));
    for (name, value) in [
        ("count", args.count.map(Value::from)),
        ("packetsize", args.packet_size.map(Value::from)),
        (
            "source-interface",
            args.source_interface.as_deref().map(Value::from),
        ),
        ("wait-time", args.wait_time.map(Value::from)),
        ("port", args.port.map(Value::from)),
        ("time", args.time.map(Value::from)),
    ] {
        if let Some(present) = value {
            drop(body.insert(name.to_owned(), present));
        }
    }
    Value::Object(body)
}

/// Runs a `components` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes, and the commit job, may run on after cancellation.
pub(crate) async fn components(ctx: &Ctx, command: ComponentsCommand) -> Outcome {
    let permission = match command {
        ComponentsCommand::List | ComponentsCommand::Pending => Permission::Read,
        ComponentsCommand::Commit => Permission::Destructive,
        ComponentsCommand::CheckUpdate
        | ComponentsCommand::Queue {
            action: _,
            component: _,
        }
        | ComponentsCommand::AutoUpdateChannel { channel: _ }
        | ComponentsCommand::AutoUpdateSchedule { schedule: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        ComponentsCommand::List => {
            return session.show(&components::read_components(router).await?);
        }
        ComponentsCommand::Pending => {
            return session.show(&components::read_pending(router).await?);
        }
        ComponentsCommand::Commit => return commit(ctx, &session).await,
        ComponentsCommand::CheckUpdate => components::plan_check_update(router)?,
        ComponentsCommand::Queue { action, component } => {
            let staged = match action {
                QueueChoice::Install => QueueAction::Install,
                QueueChoice::Remove => QueueAction::Remove,
            };
            components::plan_queue(router, staged, &component)?
        }
        ComponentsCommand::AutoUpdateChannel { channel } => {
            components::plan_auto_update_channel(router, &channel)?
        }
        ComponentsCommand::AutoUpdateSchedule { schedule } => {
            components::plan_auto_update_schedule(router, &schedule)?
        }
    };
    session
        .cli(&operation, components::change_request(&operation)?)
        .await
}

/// Confirms and runs the destructive component commit job.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the commit job keeps running in this process until it ends.
async fn commit(ctx: &Ctx, session: &Session<'_>) -> Outcome {
    let (services, target) = (session.services(), session.target());
    let confirmation = confirm(
        ctx.out(),
        ctx.globals(),
        Risk::Destructive,
        target.id(),
        false,
    );
    ctx.confirmed(services, target.id(), confirmation).await?;
    let changes = services
        .workflow()
        .begin(target.id(), ctx.principal().actor(), target.role(), false)
        .await?
        .with_request_id(ctx.request_id());
    let jobs = runner(ctx, services).await?;
    let events = jobs.subscribe();
    let job = components::start_commit_job(
        &jobs,
        Arc::clone(services.registry()),
        target.id().to_owned(),
        target.role(),
        changes,
        &target.router().catalog,
        true,
    )
    .await
    .map_err(|error| match error {
        CommitError::Domain(domain) => Failure::from(domain),
        CommitError::Registry(registry) => Failure::from(registry),
        CommitError::ConfirmationRequired => Failure::message(
            Exit::Policy,
            keys::CLI_CONFIRM_MISSING,
            &[("router", target.id())],
        ),
        CommitError::Job(_) | _ => Failure::text(Exit::Conflict, &error),
    })?;
    report(ctx, &job, follow(&job, events).await)
}

/// The job runner on this invocation's state directory.
///
/// # Errors
///
/// Returns state failures.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, opening only reads and marks stale local job records.
pub(crate) async fn runner(ctx: &Ctx, services: &Services) -> Outcome<Arc<JobRunner>> {
    JobRunner::open(
        ctx.state().clone(),
        Arc::clone(services.registry()),
        services.audit_log().clone(),
    )
    .await
    .map_err(|error| Failure::text(Exit::Generic, &error))
}

/// Collects `job`'s output lines until it ends.
// cancel-safe: only receives events.
async fn follow(job: &str, mut events: Receiver<JobEvent>) -> (JobStatus, Vec<String>) {
    let mut lines = Vec::new();
    loop {
        match events.recv().await {
            Ok(event) if event.id == job => {
                match event.detail {
                    Some(JobProgress::OutputLine(line)) => lines.push(line),
                    Some(JobProgress::Structured(value)) => lines.push(value.to_string()),
                    Some(_) | None => {}
                }
                if event.status != JobStatus::Running {
                    return (event.status, lines);
                }
            }
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return (JobStatus::Interrupted, lines),
        }
    }
}

/// Prints a finished job; a job that did not complete is a router failure.
///
/// # Errors
///
/// Returns output failures, or the router failure of an incomplete job.
fn report(ctx: &Ctx, job: &str, (status, lines): (JobStatus, Vec<String>)) -> Outcome {
    let out = ctx.out();
    let completed = status == JobStatus::Completed;
    let mut human = lines.clone();
    if completed {
        human.push(out.tr(keys::CLI_JOB_COMPLETED, &[("name", job)]));
    }
    out.emit(
        &json!({ "job_id": job, "status": status, "lines": lines }),
        &human.join("\n"),
    )?;
    if completed {
        Ok(())
    } else {
        Err(Failure::message(
            Exit::Router,
            keys::CLI_JOB_FAILED,
            &[("name", job)],
        ))
    }
}
