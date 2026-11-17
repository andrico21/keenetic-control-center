//! Protected sequential replay with value-free partial outcomes.

use kcc_catalog::HttpMethod;
use kcc_rci::RciError;
use serde::Serialize;
use serde_json::json;

use super::{
    ChangeSet, CliCommand, Permission, WorkflowError, authorize, map_permission, read_last_change,
};

/// Whether a replay may submit later commands after a router rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReplayPolicy {
    /// Stop before transmitting the next line after any failure.
    StopOnError,
    /// Continue after an explicit rejection; transport uncertainty always stops.
    ContinueOnRejection,
}

/// Value-free result for one submitted command, in submission order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ReplayOutcome {
    /// The router returned a successful response.
    Applied,
    /// The router returned an explicit error status.
    Rejected,
    /// Transmission failed, leaving the command's effect unknown.
    Indeterminate,
}

/// Completed replay items plus a failure refreshing state or recording the audit.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReplayResult {
    /// Results for exactly the submitted prefix, without router-controlled text.
    pub outcomes: Vec<ReplayOutcome>,
    /// A post-dispatch workflow failure, without router-controlled text.
    pub completion: Result<(), ReplayCompletionError>,
}

/// Value-free failure after replay has started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReplayCompletionError {
    /// The router's final change identity could not be read.
    ReadBack,
    /// The audit writer could not persist the result.
    Audit,
}

/// Submits separate requests so a rejected line cannot execute later lines in a chunk.
///
/// This costs one round trip per line instead of one per chunk. Router bodies are dropped
/// here because substring scrubbing cannot prove arbitrary echoed fields are secret-free.
///
/// # Errors
///
/// Returns pre-dispatch workflow failures; subsequent failures stay in the result.
// NOT cancel-safe: a line may apply before its receipt or audit is stored.
pub(super) async fn run(
    changes: &mut ChangeSet,
    commands: &[CliCommand],
    policy: ReplayPolicy,
) -> Result<ReplayResult, WorkflowError> {
    authorize(&changes.role, Permission::Migrate, &changes.router).map_err(map_permission)?;
    for command in commands {
        let validated = command.validated();
        if validated.unvalidated {
            authorize(&changes.role, Permission::RawRci, &changes.router)
                .map_err(map_permission)?;
            authorize(&changes.role, Permission::ManageRouters, &changes.router)
                .map_err(map_permission)?;
        } else {
            let wire = validated.expose_for_send();
            drop(
                changes
                    .catalog
                    .validate(&validated.path, HttpMethod::Post, wire.expose_secret())
                    .map_err(|issues| WorkflowError::CatalogValidation { issues })?,
            );
        }
    }
    let lines = commands
        .iter()
        .map(CliCommand::expose_for_send)
        .collect::<Result<Vec<_>, _>>()?;
    changes.prepare(Permission::Write).await?;
    let mut outcomes = Vec::with_capacity(commands.len());
    for line in &lines {
        let response = match changes.client.parse_batch([line.as_str()]).await {
            Ok(mut results) if results.len() == 1 => results
                .pop()
                .ok_or(RciError::Decode)
                .and_then(|result| result),
            Ok(_results) => Err(RciError::Decode),
            Err(failure) => Err(RciError::from(failure)),
        };
        let outcome = match response {
            Ok(_body) => ReplayOutcome::Applied,
            Err(RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _,
            }) => ReplayOutcome::Rejected,
            Err(_error) => ReplayOutcome::Indeterminate,
        };
        outcomes.push(outcome);
        match outcome {
            ReplayOutcome::Applied => {}
            ReplayOutcome::Rejected if policy == ReplayPolicy::ContinueOnRejection => {}
            ReplayOutcome::Rejected | ReplayOutcome::Indeterminate => break,
        }
    }
    let refreshed = match read_last_change(&changes.client).await {
        Ok(current) => {
            changes.expected = current;
            Ok(())
        }
        Err(_error) => Err(ReplayCompletionError::ReadBack),
    };
    let status = if outcomes
        .iter()
        .all(|outcome| *outcome == ReplayOutcome::Applied)
    {
        "applied_unsaved"
    } else {
        "partial_failure"
    };
    let audited = changes
        .audit_cli(
            &[],
            "router.migration_replay",
            json!({"submitted":outcomes.len(), "outcomes":outcomes}),
            status,
        )
        .await
        .map_err(|_error| ReplayCompletionError::Audit);
    Ok(ReplayResult {
        outcomes,
        completion: audited.and(refreshed),
    })
}
