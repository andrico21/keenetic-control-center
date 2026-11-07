//! `kcc_diagnostics_write` and `kcc_components_write`: operations that run as jobs.

use alloc::sync::Arc;

use kcc_app::jobs::{JobEvent, JobProgress, JobStatus};
use kcc_catalog::HttpMethod;
use kcc_domain::{
    components::{self, CommitError, QueueAction},
    diagnostics::{self, DiagnosticKind},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use super::common::{apply_cli, begin, check_op, open, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::map_domain,
        route::{Progress, parse},
        validate::{empty_object, valid_value_size},
    },
};

/// Diagnostic operations.
pub(super) const DIAGNOSTIC_OPS: &[&str] = &["ping", "ping6", "traceroute", "arping", "iperf3"];

/// Component operations.
pub(super) const COMPONENT_OPS: &[&str] = &[
    "check_update",
    "install",
    "remove",
    "commit",
    "auto_update_channel",
    "auto_update_schedule",
];

/// Arguments of the diagnostics and components write tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct JobInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms `commit` (installs queued components and reboots).
    #[serde(default)]
    confirm: bool,
    /// Component, update channel, or schedule name.
    #[serde(default)]
    value: Option<String>,
    /// Diagnostic arguments, validated against the router's catalog (e.g. `{"host": "192.0.2.1"}`).
    #[serde(default = "empty_object")]
    arguments: Value,
}

/// Forwards one job's events as progress notifications until it ends.
async fn follow(
    job: &str,
    mut events: broadcast::Receiver<JobEvent>,
    progress: &Progress,
) -> Value {
    let mut sent = 0_u32;
    loop {
        match events.recv().await {
            Ok(event) if event.id == job => {
                sent = sent.saturating_add(1);
                let message = match &event.detail {
                    Some(JobProgress::OutputLine(line)) => line.clone(),
                    Some(JobProgress::Structured(_) | _) | None => format!("{}%", event.progress),
                };
                progress.notify(sent, message).await;
                if !matches!(event.status, JobStatus::Running) {
                    return json!(event.status);
                }
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return Value::Null,
        }
    }
}

/// The started job, followed to its end when the client asked for progress.
async fn started(
    job: String,
    events: broadcast::Receiver<JobEvent>,
    progress: Option<Progress>,
) -> Value {
    match progress {
        Some(progress) => {
            let status = follow(&job, events, &progress).await;
            json!({ "job_id": job, "status": status })
        }
        None => json!({ "job_id": job, "status": "running" }),
    }
}

/// Starts one catalog-validated diagnostic job.
pub(super) async fn diagnostics(
    server: &KccMcp,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let input: JobInput = parse(arguments)?;
    check_op(DIAGNOSTIC_OPS, &input.op)?;
    valid_value_size(&input.arguments)?;
    let opened = open(
        server,
        Area::Diagnostics,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let (_identity, router, ctx) = &opened;
    let kind = match input.op.as_str() {
        "ping" => DiagnosticKind::Ping,
        "ping6" => DiagnosticKind::Ping6,
        "traceroute" => DiagnosticKind::Traceroute,
        "arping" => DiagnosticKind::Arping,
        _ => DiagnosticKind::Iperf3,
    };
    let validated = ctx
        .catalog
        .validate(kind.catalog_path(), HttpMethod::Post, &input.arguments)
        .map_err(|issues| {
            tracing::warn!(?issues, "MCP diagnostic validation failed");
            McpFailure::ValidationFailed
        })?;
    let events = server.jobs.subscribe();
    let job = diagnostics::start_job(
        &server.jobs,
        router.as_str().to_owned(),
        Arc::clone(&ctx.client),
        kind,
        validated.value,
    )
    .await
    .map_err(|error| {
        tracing::warn!(error = ?error, "MCP diagnostic did not start");
        McpFailure::Conflict
    })?;
    Ok(started(job, events, progress).await)
}

/// Runs one component write; `commit` starts the confirmed install-and-reboot job.
pub(super) async fn components(
    server: &KccMcp,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let input: JobInput = parse(arguments)?;
    check_op(COMPONENT_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Components,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let (identity, router, ctx) = &opened;
    let planned = match input.op.as_str() {
        "check_update" => components::plan_check_update(ctx),
        "install" => {
            components::plan_queue(ctx, QueueAction::Install, text(input.value.as_deref())?)
        }
        "remove" => components::plan_queue(ctx, QueueAction::Remove, text(input.value.as_deref())?),
        "auto_update_channel" => {
            components::plan_auto_update_channel(ctx, text(input.value.as_deref())?)
        }
        "auto_update_schedule" => {
            components::plan_auto_update_schedule(ctx, text(input.value.as_deref())?)
        }
        _ => {
            let changes = begin(server, &opened).await?;
            let events = server.jobs.subscribe();
            let job = components::start_commit_job(
                &server.jobs,
                Arc::clone(&server.registry),
                router.as_str().to_owned(),
                &identity.role,
                changes,
                &ctx.catalog,
                input.confirm,
            )
            .await
            .map_err(|error| match error {
                CommitError::ConfirmationRequired => McpFailure::InvalidArguments,
                CommitError::Domain(domain) => map_domain(domain),
                CommitError::Registry(_) | CommitError::Job(_) | _ => {
                    tracing::warn!(error = ?error, "MCP component commit did not start");
                    McpFailure::Conflict
                }
            })?;
            return Ok(started(job, events, progress).await);
        }
    };
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, components::change_request),
    )
    .await
}
