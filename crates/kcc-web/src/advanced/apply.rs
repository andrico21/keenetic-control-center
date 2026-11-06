//! Protected changes through the change workflow.
//!
//! Every execution that is not read-only runs inside a leased change set (permission and
//! scope, one pre-change backup per window, conflict check, audit). A management change
//! is also wrapped in the router's fail-safe timer: armed before the change, disarmed
//! afterwards when the router still answers.

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
    workflow::{
        BatchChangeRequest, BatchItem, ChangeSet, CliChangeRequest, CliCommand, DeleteRequest,
        WorkflowError,
    },
};
use kcc_catalog::Risk;
use kcc_domain::{RouterCtx, configuration::SafetyNet};
use kcc_rci::{RciBody, RciError, RciResponse};
use serde_json::Value;

use super::{context::Target, facts::RouterFacts, gate::FAIL_SAFE_SECONDS};
use crate::authz::CurrentUser;

/// A validated change.
pub(crate) enum Change {
    /// Root RCI items, sent as one batch.
    Batch(Vec<BatchItem>),
    /// CLI lines, sent with `parse`.
    Cli(Vec<CliCommand>),
    /// One deletion.
    Delete(DeleteRequest),
}

/// The router's answer to an applied change.
pub(crate) enum Applied {
    /// One result per batch item.
    Batch(Vec<Result<RciResponse, RciError>>),
    /// One answer per CLI line.
    Cli(Vec<RciBody>),
    /// The deletion completed.
    Delete,
}

/// A change that did not complete.
pub(crate) struct Refused {
    /// Why.
    error: WorkflowError,
    /// Whether the fail-safe timer was left armed, so the router rolls back by itself.
    armed: bool,
}

impl Refused {
    /// A failure with no timer armed.
    const fn plain(error: WorkflowError) -> Self {
        Self {
            error,
            armed: false,
        }
    }

    /// Why the change did not complete.
    pub(crate) const fn error(&self) -> &WorkflowError {
        &self.error
    }

    /// Whether the fail-safe timer was left armed.
    pub(crate) const fn armed(&self) -> bool {
        self.armed
    }
}

/// Who applies a change to which router, at which risk.
pub(crate) struct Plan<'call> {
    /// The router and its services.
    target: Target<'call>,
    /// The router's catalog facts.
    facts: &'call RouterFacts,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Catalog risk of the change.
    risk: Risk,
    /// Redacted audit parameters.
    params: Value,
}

impl<'call> Plan<'call> {
    /// `user` applies a change of `risk` to `target`.
    pub(crate) const fn new(
        target: Target<'call>,
        facts: &'call RouterFacts,
        user: &'call CurrentUser,
    ) -> Self {
        Self {
            target,
            facts,
            user,
            risk: Risk::Write,
            params: Value::Null,
        }
    }

    /// Sets the catalog risk and the redacted audit parameters.
    pub(crate) fn with(mut self, risk: Risk, params: Value) -> Self {
        self.risk = risk;
        self.params = params;
        self
    }
}

/// Applies `change` as `plan` says.
///
/// # Errors
///
/// Returns the workflow error and whether the fail-safe timer stays armed.
// NOT cancel-safe: a dropped future may leave an applied change or an armed timer; the
// router's own fail-safe timer is the recovery for the latter.
pub(crate) async fn apply(plan: Plan<'_>, change: Change) -> Result<Applied, Refused> {
    let fleet = plan.target.fleet();
    let router = plan.target.router();
    let actor = Actor::new(ActorKind::Web, plan.user.username().to_owned());
    let mut changes = fleet
        .workflow()
        .begin(router, actor, plan.user.role(), None, false)
        .await
        .map_err(Refused::plain)?;
    if plan.risk != Risk::Management {
        return send(&mut changes, change, plan.params)
            .await
            .map_err(Refused::plain);
    }
    let client = fleet
        .registry()
        .client(router)
        .await
        .map_err(|error| Refused::plain(error.into()))?;
    let context = RouterCtx::new(client, plan.facts.catalog().clone());
    let mode = plan.facts.mode();
    drop(
        SafetyNet::arm(&mut changes, &context, mode, FAIL_SAFE_SECONDS)
            .await
            .map_err(Refused::plain)?,
    );
    let applied = send(&mut changes, change, plan.params).await;
    if let Err(WorkflowError::Rci(RciError::Transport | RciError::Timeout)) = &applied {
        tracing::warn!(
            router,
            "management change lost the router; fail-safe stays armed"
        );
        return applied.map_err(|error| Refused { error, armed: true });
    }
    match SafetyNet::disarm(&mut changes, &context, mode).await {
        Ok(_disarmed) => applied.map_err(Refused::plain),
        Err(error) => {
            tracing::warn!(%error, router, "fail-safe timer could not be disarmed");
            Err(Refused { error, armed: true })
        }
    }
}

/// Sends `change` through the change set.
///
/// # Errors
///
/// Returns the workflow error of the request.
// NOT cancel-safe: see `apply`.
async fn send(
    changes: &mut ChangeSet,
    change: Change,
    params: Value,
) -> Result<Applied, WorkflowError> {
    match change {
        Change::Batch(items) => changes
            .apply_batch(BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::RawRci,
                params,
            ))
            .await
            .map(|result| Applied::Batch(result.responses)),
        Change::Cli(commands) => changes
            .apply_cli(CliChangeRequest::new(
                commands,
                Vec::new(),
                Permission::RawRci,
                params,
            ))
            .await
            .map(|result| Applied::Cli(result.responses)),
        Change::Delete(request) => changes
            .apply_delete(request)
            .await
            .map(|_result| Applied::Delete),
    }
}
