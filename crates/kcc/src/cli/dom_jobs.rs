//! Diagnostic jobs, the component commit and auto-update, and the fail-safe keep-alive.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    jobs::{JobEvent, JobProgress, JobRunner, JobStatus},
    permissions::Permission,
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_domain::{
    components::{self, CommitError},
    configuration::SafetyNet,
    diagnostics::{self, DiagnosticKind},
};
use kcc_i18n::keys;
use serde_json::{Map, Value, json};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::{
    args_dom_family::Family,
    args_dom_jobs::{
        ComponentsWriteCommand, ConfigWriteCommand, DiagnosticsWriteCommand, ProbeArgs,
    },
    args_domains::DiagnosticsCommand,
    args_domains_net::ComponentsCommand,
    args_fleet::ConfigCommand,
    change::{Gate, applied},
    context::{Ctx, Services},
    dom_core, dom_net,
    domains::Session,
    exit::{Detail, Exit, Failure, Outcome},
    persist,
    secret::confirm,
};

/// Runs a `config` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn config(
    ctx: &Ctx,
    command: Family<ConfigCommand, ConfigWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => persist::config(ctx, sub).await,
        Family::Writes(sub) => config_writes(ctx, sub).await,
    }
}

/// Runs a configuration keep-alive.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the keep-alive may reach the router before cancellation.
async fn config_writes(ctx: &Ctx, command: ConfigWriteCommand) -> Outcome {
    let ConfigWriteCommand::KeepAlive = command;
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

/// Runs a `diagnostics` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn diagnostics(
    ctx: &Ctx,
    command: Family<DiagnosticsCommand, DiagnosticsWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_core::diagnostics(ctx, sub).await,
        Family::Writes(sub) => diagnostics_writes(ctx, sub).await,
    }
}

/// Runs a diagnostic job and waits for its lines.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the job keeps running in this process until it ends.
async fn diagnostics_writes(ctx: &Ctx, command: DiagnosticsWriteCommand) -> Outcome {
    let (kind, args) = match command {
        DiagnosticsWriteCommand::Ping(args) => (DiagnosticKind::Ping, args),
        DiagnosticsWriteCommand::Ping6(args) => (DiagnosticKind::Ping6, args),
        DiagnosticsWriteCommand::Traceroute(args) => (DiagnosticKind::Traceroute, args),
        DiagnosticsWriteCommand::Arping(args) => (DiagnosticKind::Arping, args),
        DiagnosticsWriteCommand::Iperf3(args) => (DiagnosticKind::Iperf3, args),
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

/// Runs a `components` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn components(
    ctx: &Ctx,
    command: Family<ComponentsCommand, ComponentsWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_net::components(ctx, sub).await,
        Family::Writes(sub) => components_writes(ctx, sub).await,
    }
}

/// Runs a component write; `commit` reboots and waits for the router to return.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the commit job keeps running in this process until it ends.
async fn components_writes(ctx: &Ctx, command: ComponentsWriteCommand) -> Outcome {
    let operation = match command {
        ComponentsWriteCommand::Commit => return commit(ctx).await,
        ComponentsWriteCommand::AutoUpdateChannel { channel } => {
            let session = Session::open(ctx, Permission::Write).await?;
            let operation = components::plan_auto_update_channel(session.router(), &channel)?;
            (session, operation)
        }
        ComponentsWriteCommand::AutoUpdateSchedule { schedule } => {
            let session = Session::open(ctx, Permission::Write).await?;
            let operation = components::plan_auto_update_schedule(session.router(), &schedule)?;
            (session, operation)
        }
    };
    let (session, planned) = operation;
    session
        .cli(&planned, components::change_request(&planned)?)
        .await
}

/// Confirms and runs the destructive component commit job.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the commit job keeps running in this process until it ends.
async fn commit(ctx: &Ctx) -> Outcome {
    let services = ctx.services().await?;
    let target = ctx.target(&services, &[Permission::Destructive]).await?;
    let confirmation = confirm(
        ctx.out(),
        ctx.globals(),
        Risk::Destructive,
        target.id(),
        false,
    );
    ctx.confirmed(&services, target.id(), confirmation).await?;
    let changes = services
        .workflow()
        .begin(target.id(), ctx.principal().actor(), target.role(), false)
        .await?
        .with_request_id(ctx.request_id());
    let jobs = runner(ctx, &services).await?;
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
// cancel-safe: opening only reads and marks stale local job records.
async fn runner(ctx: &Ctx, services: &Services) -> Outcome<Arc<JobRunner>> {
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
