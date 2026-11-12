//! Running a change through the change workflow.
//!
//! Every change runs inside a leased change set: permission and scope, one pre-change
//! backup per window, the conflict check, the read-back the plan asks for, and the audit
//! entry. A management change is also wrapped in the router's fail-safe timer: armed
//! before the change, disarmed afterwards when the router still answers.

use core::mem;

use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind, AuditError},
    permissions::Permission,
    workflow::{
        BatchChangeRequest, ChangeRequest, ChangeSet, CliChangeRequest, CliCommand, DeleteRequest,
        WorkflowError,
    },
};
use kcc_catalog::{Catalog, HttpMethod, Risk};
use kcc_domain::{
    DomainError, RouterCtx,
    configuration::{SafetyNet, recovery},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciBody, RciError, RciResponse};
use serde_json::{Value, json};

use super::{
    audit::field_names,
    confirm::{FAIL_SAFE_MINUTES, FAIL_SAFE_SECONDS},
    context::Target,
    facts::RouterFacts,
    failure::workflow_failure,
    family::Family,
    outcome::Failure,
};
use crate::{authz::CurrentUser, brackets};

#[cfg(test)]
mod persistence_tests;

/// A validated change, built by the page with its permission, read-back and redacted
/// audit parameters.
///
/// Changes after which the router's state is unknown (a reboot, a factory reset) run as
/// the domain's own functions through [`apply_with`].
pub(crate) enum Change {
    /// One structured write, such as a domain plan converted by its `change_request`.
    Request(ChangeRequest),
    /// Root RCI items, sent as one batch.
    Batch(BatchChangeRequest),
    /// CLI lines, sent with `parse`.
    Cli(CliChangeRequest),
    /// One deletion.
    Delete(DeleteRequest),
}

impl Change {
    /// What the web audit record says about the change: the catalog paths and the names
    /// of the fields it sets, never their values.
    pub(crate) fn audit_params(&self) -> Value {
        let (paths, fields): (Vec<&str>, Vec<String>) = match self {
            Self::Request(request) => (
                vec![request.catalog_path.as_str()],
                field_names(request.body.redacted()),
            ),
            Self::Delete(request) => (
                vec![request.catalog_path.as_str()],
                field_names(request.query.redacted()),
            ),
            Self::Batch(request) => (
                request
                    .items
                    .iter()
                    .map(|item| item.validated.path.as_str())
                    .collect(),
                request
                    .items
                    .iter()
                    .flat_map(|item| field_names(&item.validated.value))
                    .collect(),
            ),
            Self::Cli(request) => lines(&request.commands),
        };
        json!({ "operations": paths, "fields": fields })
    }

    /// Whether the router persists every part of the change at once, so none of it
    /// waits for a save.
    pub(crate) fn persists(&self) -> bool {
        match self {
            Self::Batch(request) => {
                !request.items.is_empty()
                    && request
                        .items
                        .iter()
                        .all(|item| item.validated.persists_immediately)
            }
            Self::Cli(request) => {
                !request.commands.is_empty()
                    && request
                        .commands
                        .iter()
                        .all(|command| command.validated().persists_immediately)
            }
            Self::Request(_) | Self::Delete(_) => false,
        }
    }

    /// Catalog paths of leaf commands persisted by the router at once.
    pub(crate) fn persisted_paths(&self, catalog: &Catalog) -> Vec<String> {
        match self {
            Self::Batch(request) => request
                .items
                .iter()
                .flat_map(|item| item.validated.persisted_paths.iter().cloned())
                .collect(),
            Self::Cli(request) => request
                .commands
                .iter()
                .flat_map(|command| command.validated().persisted_paths.iter().cloned())
                .collect(),
            Self::Request(request) => catalog
                .validate(
                    &request.catalog_path,
                    HttpMethod::Post,
                    request.body.expose_for_send().expose_secret(),
                )
                .map(|validated| validated.persisted_paths)
                .unwrap_or_default(),
            Self::Delete(request) => catalog
                .validate(
                    &request.catalog_path,
                    HttpMethod::Delete,
                    request.query.expose_for_send().expose_secret(),
                )
                .map(|validated| validated.persisted_paths)
                .unwrap_or_default(),
        }
    }
}

/// The catalog paths and field names of CLI lines.
fn lines(commands: &[CliCommand]) -> (Vec<&str>, Vec<String>) {
    (
        commands
            .iter()
            .map(|command| command.validated().path.as_str())
            .collect(),
        commands
            .iter()
            .flat_map(|command| field_names(&command.validated().value))
            .collect(),
    )
}

/// The router's answer to an applied change.
pub(crate) enum Applied {
    /// A write read back as planned, or a deletion.
    Done {
        /// Whether the router now has unsaved changes.
        unsaved: bool,
    },
    /// One result per batch item.
    Batch {
        /// Successful management change items.
        applied_management_changes: usize,
        /// Whether the router now has unsaved changes.
        unsaved: bool,
        /// Whether every successful item was persisted immediately.
        persists_immediately: bool,
        /// Persisted paths from successful items only.
        persisted_paths: Vec<String>,
        /// Ordered per-item answers, refusals included.
        responses: Vec<Result<RciResponse, RciError>>,
    },
    /// One answer per CLI line.
    Cli {
        /// Whether the router now has unsaved changes.
        unsaved: bool,
        /// Ordered answers.
        responses: Vec<RciBody>,
    },
    /// The answers to terminal lines; the router's state is unknown now.
    Terminal(Vec<RciBody>),
}

impl Applied {
    /// Whether the router now has unsaved changes; unknown after a terminal change.
    pub(crate) const fn unsaved(&self) -> bool {
        match self {
            Self::Done { unsaved }
            | Self::Batch {
                applied_management_changes: _,
                unsaved,
                persists_immediately: _,
                persisted_paths: _,
                responses: _,
            }
            | Self::Cli {
                unsaved,
                responses: _,
            } => *unsaved,
            Self::Terminal(_) => false,
        }
    }
}

/// A change that did not complete.
pub(crate) struct Refused {
    /// Why.
    error: Box<WorkflowError>,
    /// Whether the fail-safe timer was left armed, so the router rolls back by itself.
    armed: bool,
    /// Whether application succeeded before recovery cleanup failed.
    applied: bool,
    /// Item refusals retained when cleanup fails after a completed batch.
    refusals: Vec<RciError>,
}

impl Refused {
    /// Converts the domain verification gate into the normal failed outcome.
    pub(crate) fn verification(error: DomainError) -> Self {
        if let DomainError::Workflow(source) = error {
            Self::plain(source)
        } else {
            Self::plain(WorkflowError::InvalidResponse)
        }
    }

    /// A failure with no timer armed.
    fn plain(error: WorkflowError) -> Self {
        Self {
            error: Box::new(error),
            armed: false,
            applied: false,
            refusals: Vec::new(),
        }
    }

    /// Why the change did not complete, in `family`'s words: the router rolling back by
    /// itself when the fail-safe timer stayed armed, else the workflow error.
    pub(crate) fn failure(&self, family: Family, locale: Locale) -> Failure {
        if self.armed {
            let mut args = FluentArgs::new();
            args.set("minutes", FAIL_SAFE_MINUTES.to_string());
            let key = if self.applied {
                keys::MANAGEMENT_DISARM_FAILED
            } else if matches!(
                *self.error,
                WorkflowError::Rci(RciError::Transport | RciError::Timeout)
            ) {
                keys::WEB_EXPLORER_ARMED
            } else {
                keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
            };
            let mut messages = Vec::new();
            for error in &self.refusals {
                if let RciError::Rci {
                    message,
                    pointer: _,
                    code: _,
                    ident: _,
                } = error
                {
                    messages.push(message.clone());
                }
            }
            if let WorkflowError::Rci(RciError::Rci {
                message,
                pointer: _,
                code: _,
                ident: _,
            }) = self.error.as_ref()
            {
                messages.push(message.clone());
            }
            return Failure::new(tr(locale, key, Some(&args)), "fail_safe_armed")
                .with_router_said(messages);
        }
        workflow_failure(family, locale, &self.error)
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
    /// Management recovery remains required when a destructive sibling raises risk.
    management: bool,
}

impl<'call> Plan<'call> {
    /// `user` applies a write to `target`.
    pub(crate) const fn new(
        target: Target<'call>,
        facts: &'call RouterFacts,
        user: &'call CurrentUser,
    ) -> Self {
        Self {
            target,
            facts,
            user,
            management: false,
        }
    }

    /// Sets the risk of the change.
    pub(crate) const fn at(mut self, risk: Risk) -> Self {
        self.management = matches!(risk, Risk::Management);
        self
    }
}

/// Applies `change` as `plan` says.
///
/// # Errors
///
/// Returns the workflow error and whether the fail-safe timer stays armed.
// NOT cancel-safe: see `apply_with`.
pub(crate) async fn apply(mut plan: Plan<'_>, change: Change) -> Result<Applied, Refused> {
    let management = match &change {
        Change::Batch(request) if request.permission == Permission::RawRci => request
            .items
            .iter()
            .any(|item| item.validated.contains_management()),
        Change::Cli(request) if request.permission == Permission::RawRci => request
            .commands
            .iter()
            .any(|command| command.validated().contains_management()),
        Change::Delete(request) if request.permission == Permission::RawRci => plan
            .facts
            .catalog()
            .validate(
                &request.catalog_path,
                HttpMethod::Delete,
                request.query.expose_for_send().expose_secret(),
            )
            .is_ok_and(|validated| validated.contains_management()),
        Change::Request(_) | Change::Delete(_) | Change::Batch(_) | Change::Cli(_) => false,
    };
    plan.management |= management;
    apply_with(plan, async move |changes, _context| {
        send(changes, change).await
    })
    .await
}

/// Runs `work` in a leased change set for `plan`, with the router's domain context; a
/// management change runs inside the fail-safe timer.
///
/// Before it arms, it holds its request (`brackets::hold`), so that nothing cancels the
/// request until it has ended.
///
/// # Errors
///
/// Returns the workflow error and whether the fail-safe timer stays armed.
// NOT cancel-safe before the arm: a dropped future may leave an applied ordinary change.
// From the arm on the request is held and is not dropped before it disarms and reports.
pub(crate) async fn apply_with<W>(plan: Plan<'_>, work: W) -> Result<Applied, Refused>
where
    W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Result<Applied, WorkflowError>,
{
    let fleet = plan.target.fleet();
    let router = plan.target.router();
    fleet.workflow().audit_alive().map_err(Refused::plain)?;
    if plan.management
        && !super::gate::allowed(plan.user, router, SafetyNet::management_permissions())
    {
        return Err(Refused::plain(WorkflowError::PermissionDenied {
            router: router.to_owned(),
        }));
    }
    let actor = Actor::new(ActorKind::Web, plan.user.username().to_owned());
    let mut changes = fleet
        .workflow()
        .begin(router, actor, plan.user.role(), None, false)
        .await
        .map_err(Refused::plain)?;
    let client = fleet
        .registry()
        .client(router)
        .await
        .map_err(|error| Refused::plain(error.into()))?;
    let context = RouterCtx::new(client, plan.facts.catalog().clone());
    if !plan.management {
        return work(&mut changes, &context).await.map_err(Refused::plain);
    }
    if !brackets::hold() {
        tracing::warn!("management change refused: its request has no server owner");
        return Err(Refused::plain(WorkflowError::Audit(
            AuditError::WriterUnavailable,
        )));
    }
    let mode = plan.facts.mode();
    let arm_result = SafetyNet::arm(&mut changes, &context, mode, FAIL_SAFE_SECONDS)
        .await
        .map(|_receipt| ());
    if let Err(error) = arm_result {
        let disarm = SafetyNet::disarm(&mut changes, &context, mode).await;
        return recovery::finish(Err(error), disarm).map_err(|failure| {
            let armed = failure.is_armed();
            Refused {
                error: Box::new(failure.into_source()),
                armed,
                applied: false,
                refusals: Vec::new(),
            }
        });
    }
    let applied = work(&mut changes, &context).await;
    let disarm = SafetyNet::disarm(&mut changes, &context, mode).await;
    let completed = applied.as_ref().is_ok_and(|value| match value {
        Applied::Batch {
            applied_management_changes,
            unsaved: _,
            persists_immediately: _,
            persisted_paths: _,
            responses: _,
        } => *applied_management_changes != 0,
        Applied::Done { unsaved: _ }
        | Applied::Cli {
            unsaved: _,
            responses: _,
        }
        | Applied::Terminal(_) => true,
    });
    let mut refusals = Vec::new();
    let completion = applied.map(|mut value| {
        if disarm.is_err()
            && let Applied::Batch {
                responses,
                applied_management_changes: _,
                unsaved: _,
                persists_immediately: _,
                persisted_paths: _,
            } = &mut value
        {
            refusals = mem::take(responses)
                .into_iter()
                .filter_map(Result::err)
                .collect();
        }
        value
    });
    recovery::finish_applied(completion, disarm, completed).map_err(|failure| {
        let armed = failure.is_armed();
        let known_applied = failure.applied();
        Refused {
            error: Box::new(failure.into_source()),
            armed,
            applied: known_applied,
            refusals,
        }
    })
}

/// Sends `change` through the change set.
///
/// # Errors
///
/// Returns the workflow error of the request.
// NOT cancel-safe: see `apply_with`.
async fn send(changes: &mut ChangeSet, change: Change) -> Result<Applied, WorkflowError> {
    match change {
        Change::Request(request) => changes.apply(request).await.map(|result| Applied::Done {
            unsaved: result.unsaved,
        }),
        Change::Batch(request) => changes
            .apply_batch(request)
            .await
            .map(|result| Applied::Batch {
                applied_management_changes: result.applied_management_changes,
                unsaved: result.unsaved,
                persists_immediately: result.persists_immediately,
                persisted_paths: result.persisted_paths,
                responses: result.responses,
            }),
        Change::Cli(request) => changes.apply_cli(request).await.map(|result| Applied::Cli {
            unsaved: result.unsaved,
            responses: result.responses,
        }),
        Change::Delete(request) => {
            changes
                .apply_delete(request)
                .await
                .map(|result| Applied::Done {
                    unsaved: result.unsaved,
                })
        }
    }
}
