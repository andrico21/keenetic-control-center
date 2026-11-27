//! One change a domain page makes on a router: the kit call.
//!
//! A page opens an [`Operation`] of its domain on the router of its route: the router is
//! resolved and checked, the operation's permissions are checked again (a hidden control
//! is not a permission check) and the router's catalog is loaded. The page then plans its
//! change with the domain, asks for the confirmation the change's risk needs and runs it
//! through the change workflow. The action audits how it ended, once, with field names
//! only, and returns the outcome to render ([`ending`]).

mod described;
mod ending;

use axum::{
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_catalog::{Catalog, Risk};
use kcc_domain::{DomainDescriptor, RouterCtx, configuration::SafetyNet, verification};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::json;

use self::described::Source;
use super::{
    audit::Record,
    change::{self, Applied, Change, Plan, Refused},
    confirm::{Confirmation, Resubmit, Stakes},
    context::{self, Target, fragment_shell},
    facts::RouterFacts,
    family::Family,
    gate::{Controls, allowed},
    outcome::{Failure, Outcome},
    respond::Answer,
    submit::{Planned, work::Job},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
};

/// What running a write takes: its catalog command, the permission it needs and its risk.
#[derive(Debug, Clone, Copy)]
struct Described {
    /// Catalog command of the write.
    catalog_path: &'static str,
    /// Permission the write needs.
    permission: Permission,
    /// The write's risk.
    risk: Risk,
}

/// A curated write of a domain, as a page runs it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Operation {
    /// Where the write is described.
    source: Source,
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
            source: Source::Listed(domain, name),
            action,
        }
    }

    /// A write its domain plans without listing it in its descriptor, such as an Entware
    /// setting: the catalog command `catalog_path`, the `permission` and `risk` its
    /// planner checks, audited as `action`.
    pub(crate) const fn planned(
        catalog_path: &'static str,
        (permission, risk): (Permission, Risk),
        action: &'static str,
    ) -> Self {
        Self {
            source: Source::Planned(Described {
                catalog_path,
                permission,
                risk,
            }),
            action,
        }
    }

    /// The description of the write; `None` is a page bug.
    fn descriptor(self) -> Option<Described> {
        self.source.described()
    }

    /// Whether a page offers the write: the role holds what it needs (`controls`) and the
    /// router's `catalog` has its command; [`Self::open`] checks the same permissions.
    pub(crate) fn offered(self, controls: &Controls, catalog: &Catalog) -> bool {
        self.descriptor().is_some_and(|described| {
            catalog.lookup(described.catalog_path).is_some()
                && controls.permits(&SafetyNet::required(described.permission, described.risk))
        })
    }

    /// Opens the operation on `router` for `user`.
    ///
    /// # Errors
    ///
    /// The answer instead: 404 or 503 when the router is not visible, the audited 403 when
    /// the role lacks the operation's permissions, the outcome naming the problem when
    /// the router's catalog is unknown, the logged 500 for a write the domain lacks.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, it only reads, but a refusal or a failed detection queues
    // an audit entry that may be written after the future is dropped.
    pub(crate) async fn open<'call>(
        self,
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Result<Action<'call>, Answer> {
        let locale = user.locale();
        if state.audit().require_alive().is_err() {
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response().into());
        }
        let target = context::target(state, user, router)
            .await
            .map_err(context::Refusal::status)?;
        let Some(descriptor) = self.descriptor() else {
            let error = format!("domain write of {} is not described", self.action);
            return Err(errors::internal(&error, fragment_shell(locale)).into());
        };
        let record = Record::on_router(self.action, router, descriptor.catalog_path.to_owned());
        if !allowed(
            user,
            router,
            &SafetyNet::required(descriptor.permission, descriptor.risk),
        ) {
            record.append(state, user, "forbidden").await;
            return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
        }
        let facts = match target.facts(state).await {
            Ok(facts) => facts,
            Err(error) => {
                let failure = ending::unknown(locale, &error);
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
    /// The description of the operation.
    descriptor: Described,
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
    // NOT cancel-safe: a missing client queues an audit entry that may be written after the future
    // is dropped; otherwise it only builds or reuses the client and sends nothing.
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

    /// The confirmation a change of `stakes` needs: the dialog to show until the
    /// submitted `confirmation` is enough, which then sends the request again by
    /// `resubmit`.
    pub(crate) fn confirm(
        &self,
        stakes: Stakes,
        confirmation: &Confirmation,
        resubmit: Resubmit,
    ) -> Option<Response> {
        self.effective(stakes)
            .ask(self.family, confirmation, self.router())
            .map(|prompt| {
                prompt
                    .named(self.state.router_name(self.router()))
                    .render(resubmit, self.locale())
            })
    }

    /// `stakes`, never below the operation's own described risk.
    pub(crate) fn effective(&self, stakes: Stakes) -> Stakes {
        stakes.at_least(self.descriptor.risk)
    }

    /// Whether the role holds what a change of `stakes` needs.
    pub(crate) fn may_take(&self, stakes: Stakes) -> bool {
        allowed(
            self.user,
            self.router(),
            &SafetyNet::required(self.descriptor.permission, self.effective(stakes).risk()),
        )
    }

    /// Ends the action before anything was sent, audited as `reason`, such as
    /// `validation_failed`.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn abandon(self, reason: &'static str) {
        self.record.append(self.state, self.user, reason).await;
    }

    /// Runs `planned` at the risk the domain planned it at, through the change workflow,
    /// and audits how it ended; the outcome carries what the work reported beyond it.
    // NOT cancel-safe: see `change::apply_with`.
    pub(crate) async fn run_planned(self, planned: Planned) -> Outcome {
        let (stakes, job) = planned.into_parts();
        match job {
            Job::Change(change) => self.run(stakes, change).await,
            Job::Work(work) => {
                let mut report = None;
                let outcome = self
                    .run_with(stakes, async |changes, context| {
                        let worked = work(changes, context).await;
                        worked.map_err(|stopped| stopped.into_error(&mut report))
                    })
                    .await;
                outcome.with_report(report)
            }
        }
    }

    /// Runs `change`, planned at `stakes`, through the change workflow and audits how it
    /// ended. A batch of root RCI items is the command pages' own and never runs here.
    // NOT cancel-safe: see `change::apply_with`.
    async fn run(self, stakes: Stakes, change: Change) -> Outcome {
        let params = change.audit_params();
        let verified_change = match change {
            Change::Cli(request) => match verification::complete(request) {
                Ok(verified) => Change::Cli(verified),
                Err(error) => {
                    let refused = Err(Refused::verification(error));
                    return ending::finished(self, params, refused).await;
                }
            },
            Change::Batch(..) => {
                tracing::error!("a domain page planned a batch; nothing was sent");
                let message = tr(self.locale(), keys::WEB_ERROR_INTERNAL_TEXT, None);
                let failure = Failure::new(message, "internal");
                return ending::stopped(self, params, failure).await;
            }
            other @ (Change::Request(_) | Change::Delete(_)) => other,
        };
        if let Change::Cli(request) = &verified_change
            && let Err(error) = verification::require(request)
        {
            return ending::finished(self, params, Err(Refused::verification(error))).await;
        }
        let Some(plan) = self.plan(stakes) else {
            let failure = Failure::forbidden(self.locale());
            return ending::stopped(self, params, failure).await;
        };
        let result = change::apply(plan, verified_change).await;
        ending::finished(self, params, result).await
    }

    /// Runs `work`, a domain function on the leased change set, at `stakes` and audits
    /// how it ended.
    // NOT cancel-safe: see `change::apply_with`.
    async fn run_with<W>(self, stakes: Stakes, work: W) -> Outcome
    where
        W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Result<Applied, WorkflowError>,
    {
        let params = json!({ "operations": [self.descriptor.catalog_path] });
        let Some(plan) = self.plan(stakes) else {
            let failure = Failure::forbidden(self.locale());
            return ending::stopped(self, params, failure).await;
        };
        let result = change::apply_with(plan, self.descriptor.permission, work).await;
        ending::finished(self, params, result).await
    }

    /// The change-workflow plan at `stakes` (never below the operation's own risk), when
    /// the role holds what they need.
    fn plan(&self, stakes: Stakes) -> Option<Plan<'_>> {
        self.may_take(stakes)
            .then(|| Plan::new(self.target, &self.facts, self.user).at(self.effective(stakes)))
    }
}
