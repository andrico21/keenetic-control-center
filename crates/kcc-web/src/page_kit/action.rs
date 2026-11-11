//! One change a domain page makes on a router: the kit call.
//!
//! A page opens an [`Operation`] of its domain on the router of its route: the router is
//! resolved and checked, the operation's permissions are checked again (a hidden control
//! is not a permission check) and the router's catalog is loaded. The page then plans its
//! change with the domain, asks for the confirmation the change's risk needs and runs it
//! through the change workflow. The action audits how it ended, once, with field names
//! only, and returns the outcome to render.

use axum::response::Response;
use kcc_app::workflow::{ChangeSet, WorkflowError};
use kcc_catalog::Risk;
use kcc_domain::{DomainDescriptor, OperationDescriptor, RouterCtx, verification};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::{Value, json};

use super::{
    audit::Record,
    change::{self, Applied, Change, Plan, Refused},
    confirm::{Confirmation, Resubmit},
    context::{self, Target, fragment_shell},
    facts::{FactsError, RouterFacts},
    family::Family,
    gate::{allowed, operation_permissions},
    outcome::{Failure, Outcome},
    respond::Answer,
    stakes::Stakes,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
};

/// A curated write of a domain, as a page runs it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Operation {
    /// The domain whose write it is.
    domain: &'static DomainDescriptor,
    /// The write's name in the domain descriptor.
    name: &'static str,
    /// Stable audit action id, such as `web.system_hostname`.
    action: &'static str,
}

impl Operation {
    /// The write `name` of `domain`, audited as `action`.
    pub(crate) const fn write(
        domain: &'static DomainDescriptor,
        name: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            domain,
            name,
            action,
        }
    }

    /// The domain's description of the write; `None` is a page bug.
    fn descriptor(self) -> Option<&'static OperationDescriptor> {
        self.domain
            .write_ops
            .iter()
            .find(|operation| operation.name == self.name)
    }

    /// Opens the operation on `router` for `user`.
    ///
    /// # Errors
    ///
    /// The answer instead: 404 or 503 when the router is not visible, the audited 403 when
    /// the role lacks the operation's permissions, the outcome naming the problem when
    /// the router's catalog is unknown, the logged 500 for a write the domain lacks.
    // cancel-safe: reads and one audit append.
    pub(crate) async fn open<'call>(
        self,
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Result<Action<'call>, Answer> {
        let locale = user.locale();
        let target = context::target(state, user, router)
            .await
            .map_err(context::Refusal::status)?;
        let Some(descriptor) = self.descriptor() else {
            let error = format!("domain write {} is not described", self.name);
            return Err(errors::internal(&error, fragment_shell(locale)).into());
        };
        let record = Record::on_router(self.action, router, descriptor.catalog_path.to_owned());
        if !allowed(
            user,
            router,
            &operation_permissions(descriptor.permission, descriptor.risk),
        ) {
            record.append(state, user, "forbidden").await;
            return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
        }
        let facts = match target.facts(state).await {
            Ok(facts) => facts,
            Err(error) => {
                let failure = unknown(locale, error);
                let outcome = Outcome::failed(failure);
                record.append(state, user, outcome.audit()).await;
                return Err(outcome.render(locale).into());
            }
        };
        Ok(Action {
            state,
            user,
            target,
            facts,
            descriptor,
            record,
            family: Family::Changes,
        })
    }
}

/// An opened operation: the router resolved, the permissions checked, the catalog known.
pub(crate) struct Action<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// The router and its services.
    target: Target<'call>,
    /// The router's catalog facts.
    facts: RouterFacts,
    /// The domain's description of the operation.
    descriptor: &'static OperationDescriptor,
    /// The audit record the action ends with.
    record: Record,
    /// The words of the domain pages.
    family: Family,
}

impl<'call> Action<'call> {
    /// The user's locale.
    pub(crate) const fn locale(&self) -> Locale {
        self.user.locale()
    }

    /// Router profile id.
    pub(crate) const fn router(&self) -> &'call str {
        self.target.router()
    }

    /// The domain context to plan with: the router's shared client and its catalog.
    ///
    /// # Errors
    ///
    /// The rendered, audited outcome when the router has no client.
    // cancel-safe: connects at most, sends no change.
    pub(crate) async fn context(&self) -> Result<RouterCtx, Answer> {
        match self.target.fleet().registry().client(self.router()).await {
            Ok(client) => Ok(RouterCtx::new(client, self.facts.catalog().clone())),
            Err(error) => {
                tracing::warn!(%error, "domain page: no router client");
                let locale = self.locale();
                let failure =
                    Failure::new(tr(locale, self.family.unreachable(), None), "unreachable");
                let outcome = Outcome::failed(failure);
                self.record
                    .clone()
                    .append(self.state, self.user, outcome.audit())
                    .await;
                Err(outcome.render(locale).into())
            }
        }
    }

    /// The confirmation a change of `risk` needs: the dialog to show until the submitted
    /// `confirmation` is enough, which then sends the request again by `resubmit`.
    pub(crate) fn confirm(
        &self,
        risk: Risk,
        confirmation: &Confirmation,
        resubmit: Resubmit,
    ) -> Option<Response> {
        let effective = risk.max(self.descriptor.risk);
        self.family
            .ask(Stakes::new(effective), confirmation, self.router())
            .map(|prompt| prompt.render(resubmit, self.locale()))
    }

    /// Ends the action before anything was sent, audited as `reason`, such as
    /// `validation_failed`.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn abandon(self, reason: &'static str) {
        self.record.append(self.state, self.user, reason).await;
    }

    /// Runs `change`, planned at `risk`, through the change workflow and audits how it
    /// ended.
    // NOT cancel-safe: see `change::apply_with`.
    pub(crate) async fn run(self, risk: Risk, change: Change) -> Outcome {
        let params = change.audit_params();
        let verified_change = match change {
            Change::Cli(request) => match verification::complete(request) {
                Ok(verified) => Change::Cli(verified),
                Err(error) => return self.finish(params, Err(Refused::verification(error))).await,
            },
            other @ (Change::Request(_) | Change::Batch(_) | Change::Delete(_)) => other,
        };
        if let Change::Cli(request) = &verified_change
            && let Err(error) = verification::require(request)
        {
            return self.finish(params, Err(Refused::verification(error))).await;
        }
        let Some(plan) = self.plan(risk) else {
            return self.forbidden(params).await;
        };
        let result = change::apply(plan, verified_change).await;
        self.finish(params, result).await
    }

    /// Runs `work`, a domain function on the leased change set, at `risk` and audits how
    /// it ended.
    // NOT cancel-safe: see `change::apply_with`.
    pub(crate) async fn run_with<W>(self, risk: Risk, work: W) -> Outcome
    where
        W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Result<Applied, WorkflowError>,
    {
        let params = json!({ "operations": [self.descriptor.catalog_path] });
        let Some(plan) = self.plan(risk) else {
            return self.forbidden(params).await;
        };
        let result = change::apply_with(plan, work).await;
        self.finish(params, result).await
    }

    /// The change-workflow plan at `risk` (never below the operation's own), when the
    /// role holds what that risk needs.
    fn plan(&self, risk: Risk) -> Option<Plan<'_>> {
        let effective = risk.max(self.descriptor.risk);
        allowed(
            self.user,
            self.router(),
            &operation_permissions(self.descriptor.permission, effective),
        )
        .then(|| Plan::new(self.target, &self.facts, self.user).at(effective))
    }

    /// The outcome of a change whose planned risk the role may not take, audited.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn forbidden(self, params: Value) -> Outcome {
        let failure = Failure::new(tr(self.locale(), keys::ERRORS_FORBIDDEN, None), "forbidden");
        let outcome = Outcome::failed(failure);
        self.record
            .with_params(params)
            .append(self.state, self.user, outcome.audit())
            .await;
        outcome
    }

    /// The outcome of `result`, audited with `params`.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn finish(self, params: Value, result: Result<Applied, Refused>) -> Outcome {
        let locale = self.locale();
        let outcome = match result {
            Ok(Applied::Terminal(_)) => {
                Outcome::done(tr(locale, self.family.done_terminal(), None), false)
            }
            Ok(applied) => {
                let unsaved = applied.unsaved();
                Outcome::done(tr(locale, self.family.done(unsaved), None), unsaved)
            }
            Err(refused) => Outcome::failed(refused.failure(self.family, locale)),
        };
        self.record
            .with_params(params)
            .append(self.state, self.user, outcome.audit())
            .await;
        outcome
    }
}

/// The failure of a router whose catalog is unknown.
fn unknown(locale: Locale, error: FactsError) -> Failure {
    let audit = match error {
        FactsError::Unreachable => "unreachable",
        FactsError::Unsupported => "unsupported",
    };
    Failure::new(tr(locale, error.message(Family::Changes), None), audit)
}
