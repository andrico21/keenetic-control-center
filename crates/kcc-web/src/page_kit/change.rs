//! Running a change through the change workflow.
//!
//! Every change runs inside a leased change set: permission and scope, one pre-change
//! backup per window, the conflict check, the read-back the plan asks for, and the audit
//! entry. A management change also runs inside the router's recovery timer, through the
//! shared safety bracket ([`kcc_domain::configuration::bracket`]): armed before the
//! change, disarmed afterwards, and reported as still armed when the disarm failed.

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
    workflow::{
        BatchChangeRequest, ChangeRequest, ChangeSet, CliChangeRequest, CliCommand, WorkflowError,
    },
};
use kcc_catalog::{Catalog, HttpMethod, ValidatedRequest};
use kcc_domain::{
    DomainError, RouterCtx,
    configuration::{SafetyMode, bracket::guarded, recovery},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::{RciBody, RciError, RciResponse};
use serde_json::{Value, json};

use super::{
    audit::field_names, confirm::Stakes, context::Target, facts::RouterFacts,
    failure::workflow_failure, family::Family, outcome::Failure,
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
    /// Root RCI items, sent as one batch, with the page's own validation of each item for
    /// its preview and audit record; the workflow validates the items again from their values.
    Batch(BatchChangeRequest, Vec<ValidatedRequest>),
    /// CLI lines, sent with `parse`.
    Cli(CliChangeRequest),
    /// One deletion.
    Delete(ChangeRequest),
}

impl Change {
    /// What the web audit record says about the change: the catalog paths and the names
    /// of the fields it sets, never their values.
    pub(crate) fn audit_params(&self) -> Value {
        let (paths, fields): (Vec<&str>, Vec<String>) = match self {
            Self::Request(request) | Self::Delete(request) => (
                vec![request.catalog_path.as_str()],
                field_names(request.body.redacted()),
            ),
            Self::Batch(_request, checks) => (
                checks
                    .iter()
                    .map(|validated| validated.path.as_str())
                    .collect(),
                checks
                    .iter()
                    .flat_map(|validated| field_names(validated.value()))
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
            Self::Batch(_request, checks) => {
                !checks.is_empty()
                    && checks
                        .iter()
                        .all(|validated| validated.persists_immediately)
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
            Self::Batch(_request, checks) => checks
                .iter()
                .flat_map(|validated| validated.persisted_paths.iter().cloned())
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
                .map_or_default(|validated| validated.persisted_paths),
            Self::Delete(request) => catalog
                .validate(
                    &request.catalog_path,
                    HttpMethod::Delete,
                    request.body.expose_for_send().expose_secret(),
                )
                .map_or_default(|validated| validated.persisted_paths),
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
            .flat_map(|command| field_names(command.validated().value()))
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

/// A change that completed.
pub(crate) struct Landed {
    /// The router's answer.
    applied: Applied,
    /// Whether an audit entry of the change is still queued behind another process's
    /// append lock; it is written once the lock is free.
    audit_pending: bool,
}

impl Landed {
    /// The router's answer, and whether an audit entry of the change is still queued.
    pub(crate) fn into_parts(self) -> (Applied, bool) {
        (self.applied, self.audit_pending)
    }
}

/// A change that did not complete.
pub(crate) struct Refused {
    /// Why.
    error: Box<WorkflowError>,
    /// What the failure says beyond its workflow error.
    said: Said,
    /// The router's words about refused batch items, kept when the recovery timer may
    /// still be armed after a completed batch.
    router_said: Vec<String>,
}

/// What a refused change's failure says beyond its workflow error.
#[derive(Clone, Copy)]
enum Said {
    /// Nothing more: the workflow error tells what happened.
    Error,
    /// The router's recovery mechanism is unknown, so nothing was sent.
    ModeUnknown,
    /// The request has no server owner any more, so nothing was sent.
    Unowned,
    /// The bracket's own outcome.
    Bracket {
        /// The message that states it.
        key: MessageKey,
        /// Whether the recovery timer may still be armed.
        armed: bool,
    },
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
        Self::said(error, Said::Error)
    }

    /// A failure that says `said`.
    fn said(error: WorkflowError, said: Said) -> Self {
        Self {
            error: Box::new(error),
            said,
            router_said: Vec::new(),
        }
    }

    /// A failed bracket; `router_said` holds the router's words about refused batch
    /// items, shown when the recovery timer may still be armed.
    fn bracket(failure: recovery::Failure<WorkflowError>, router_said: Vec<String>) -> Self {
        let armed = failure.is_armed();
        let message = failure.message_key();
        let error = failure.into_source();
        let said = match (&error, message) {
            (WorkflowError::Unowned, _) => Said::Unowned,
            (_, Some(key)) => Said::Bracket { key, armed },
            (_, None) => Said::Error,
        };
        Self {
            error: Box::new(error),
            said,
            router_said: if armed { router_said } else { Vec::new() },
        }
    }

    /// Why the change did not complete, in `family`'s words: the bracket's outcome when
    /// it decides the message, else the workflow error.
    pub(crate) fn failure(&self, family: Family, locale: Locale) -> Failure {
        match self.said {
            Said::Error => workflow_failure(family, locale, &self.error),
            Said::ModeUnknown => Failure::new(
                tr(locale, keys::MANAGEMENT_MODE_UNKNOWN, None),
                "mode_unknown",
            ),
            Said::Unowned => Failure::new(tr(locale, keys::WEB_BRACKET_UNOWNED, None), "failed"),
            Said::Bracket { key, armed } => {
                let audit = workflow_failure(family, locale, &self.error).audit();
                let mut messages = self.router_said.clone();
                if let WorkflowError::Rci(rci) = self.error.as_ref() {
                    messages.extend(router_message(rci));
                }
                let failure = Failure::new(tr(locale, key, None), audit).with_router_said(messages);
                if armed {
                    failure.with_fail_safe_armed()
                } else {
                    failure
                }
            }
        }
    }
}

/// The router's own words in `error`, when it is the router's refusal.
fn router_message(error: &RciError) -> Option<String> {
    if let RciError::Rci {
        message,
        pointer: _,
        code: _,
        ident: _,
    } = error
    {
        Some(message.clone())
    } else {
        None
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
    /// Whether the change runs inside the router's recovery timer.
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

    /// Sets the stakes of the change: a management change runs inside the recovery
    /// timer, whatever risk its other operations raise it to.
    pub(crate) const fn at(mut self, stakes: Stakes) -> Self {
        self.management = stakes.management();
        self
    }
}

/// Applies `change` as `plan` says.
///
/// # Errors
///
/// Returns the workflow error and whether the fail-safe timer stays armed.
// NOT cancel-safe: see `apply_with`.
pub(crate) async fn apply(mut plan: Plan<'_>, change: Change) -> Result<Landed, Refused> {
    let (management, permission) = match &change {
        Change::Batch(request, checks) => (
            request.permission == Permission::RawRci
                && checks.iter().any(ValidatedRequest::contains_management),
            request.permission,
        ),
        Change::Cli(request) => (
            request.permission == Permission::RawRci
                && request
                    .commands
                    .iter()
                    .any(|command| command.validated().contains_management()),
            request.permission,
        ),
        Change::Delete(request) => (
            request.permission == Permission::RawRci
                && plan
                    .facts
                    .catalog()
                    .validate(
                        &request.catalog_path,
                        HttpMethod::Delete,
                        request.body.expose_for_send().expose_secret(),
                    )
                    .is_ok_and(|validated| validated.contains_management()),
            request.permission,
        ),
        Change::Request(request) => (false, request.permission),
    };
    plan.management |= management;
    apply_with(plan, permission, async move |changes, _context| {
        send(changes, change).await
    })
    .await
}

/// Runs `work` in a leased change set for `plan`, with the router's domain context.
///
/// A management change runs inside the router's recovery timer, through the shared
/// bracket, authorized by `permission`, the permission of the change.
///
/// Before the first change reaches the router it holds its request (`brackets::hold`),
/// so that neither the request budget nor a browser that leaves cancels a write the
/// router may have received: it ends, and is audited, as if somebody still waited.
///
/// # Errors
///
/// Returns the workflow error and whether the fail-safe timer stays armed.
// NOT cancel-safe until it holds its request: dropped earlier, nothing was sent. From the
// hold on the request is not dropped before the work ends, disarms and reports.
pub(crate) async fn apply_with<W>(
    plan: Plan<'_>,
    permission: Permission,
    work: W,
) -> Result<Landed, Refused>
where
    W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Result<Applied, WorkflowError>,
{
    let fleet = plan.target.fleet();
    let router = plan.target.router();
    fleet.workflow().audit_alive().map_err(Refused::plain)?;
    let actor = Actor::new(ActorKind::Web, plan.user.username().to_owned());
    let mut changes = fleet
        .workflow()
        .begin(router, actor, plan.user.role(), false)
        .await
        .map_err(Refused::plain)?;
    let client = fleet
        .registry()
        .client(router)
        .await
        .map_err(|error| Refused::plain(error.into()))?;
    let context = RouterCtx::new(client, plan.facts.catalog().clone());
    let mode =
        if plan.management {
            Some(SafetyMode::for_change(&changes).map_err(|_unknown| {
                Refused::said(WorkflowError::InvalidResponse, Said::ModeUnknown)
            })?)
        } else {
            None
        };
    if !brackets::hold() {
        tracing::warn!("change refused: its request has no server owner");
        return Err(Refused::said(WorkflowError::Unowned, Said::Unowned));
    }
    let Some(safety) = mode else {
        let applied = work(&mut changes, &context).await.map_err(Refused::plain)?;
        return Ok(Landed {
            applied,
            audit_pending: changes.audit_pending(),
        });
    };
    let mut refused_items = Vec::new();
    let stash = &mut refused_items;
    let applied = guarded(
        &mut changes,
        &context,
        safety,
        permission,
        brackets::hold,
        async move |leased, router_ctx| {
            let applied = work(leased, router_ctx).await?;
            let completed = match &applied {
                Applied::Batch {
                    applied_management_changes,
                    unsaved: _,
                    persists_immediately: _,
                    persisted_paths: _,
                    responses,
                } => {
                    *stash = responses
                        .iter()
                        .filter_map(|response| response.as_ref().err().and_then(router_message))
                        .collect();
                    *applied_management_changes != 0
                }
                Applied::Done { unsaved: _ }
                | Applied::Cli {
                    unsaved: _,
                    responses: _,
                }
                | Applied::Terminal(_) => true,
            };
            Ok((applied, completed))
        },
    )
    .await
    .map_err(|failure| Refused::bracket(failure, refused_items))?;
    Ok(Landed {
        applied,
        audit_pending: changes.audit_pending(),
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
        Change::Batch(request, _checks) => {
            changes
                .apply_batch(request)
                .await
                .map(|result| Applied::Batch {
                    applied_management_changes: result.applied_management_changes,
                    unsaved: result.unsaved,
                    persists_immediately: result.persists_immediately,
                    persisted_paths: result.persisted_paths,
                    responses: result.responses,
                })
        }
        Change::Cli(request) => changes.apply_cli(request).await.map(|result| Applied::Cli {
            unsaved: result.unsaved,
            responses: result.responses,
        }),
        Change::Delete(request) => changes.apply(request).await.map(|result| Applied::Done {
            unsaved: result.unsaved,
        }),
    }
}
