//! One in-memory migration record: the plan, its report, and after apply its job and
//! write lease.
//!
//! A `MigrationPlan` carries executable commands in secret buffers and deliberately cannot
//! be deserialized, so plans and the applier's write lease live only in this process; a
//! restart forgets them while any armed router safety timer still rolls the router back.

use core::time::Duration;

use kcc_migrate::{
    apply::{Applier, ApplyReport},
    planner::MigrationPlan,
    report::MigrationReport,
};
use serde_json::{Value, json};

use crate::{McpFailure, McpIdentity, RouterId};

/// One planned migration and, after apply, its job and write lease.
#[derive(Debug)]
pub(crate) struct Migration {
    /// Identity that created the plan.
    owner: String,
    /// Source router.
    source: RouterId,
    /// Target router.
    target: RouterId,
    /// Reviewed executable plan.
    plan: MigrationPlan,
    /// Router-qualified id exposed by MCP and used as the map key.
    id: String,
    /// Redacted report of the plan.
    report: MigrationReport,
    /// Whole-source index of each planned source setting.
    kept: Vec<usize>,
    /// Apply job id.
    job: Option<String>,
    /// Lease retained for commit or rollback.
    applier: Option<Applier>,
    /// Last apply report after a terminal finish releases the lease.
    applied: Option<ApplyReport>,
}

impl Migration {
    /// Records a new plan, its report, and the whole-source index of each planned setting.
    pub(crate) fn new(
        owner: String,
        routers: (RouterId, RouterId),
        planned: (MigrationPlan, MigrationReport, Vec<usize>),
    ) -> Self {
        let (source, target) = routers;
        let (plan, report, kept) = planned;
        let id = format!("{}{plan_id}", target.as_str(), plan_id = plan.plan_id);
        Self {
            owner,
            source,
            target,
            plan,
            id,
            report,
            kept,
            job: None,
            applier: None,
            applied: None,
        }
    }

    /// Refuses callers other than the owner; returns both routers for authorization.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(crate) fn routers_for(&self, identity: &McpIdentity) -> Result<[RouterId; 2], McpFailure> {
        if self.owner != identity.name {
            return Err(McpFailure::Forbidden);
        }
        Ok([self.source.clone(), self.target.clone()])
    }

    /// The reviewed plan.
    pub(crate) const fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// Whether an apply already produced a lease.
    pub(crate) const fn applied(&self) -> bool {
        self.applier.is_some() || self.applied.is_some()
    }

    /// Stores the apply job and its lease.
    pub(crate) fn record_apply(&mut self, job: String, applier: Applier) {
        self.job = Some(job);
        self.applier = Some(applier);
    }

    /// The lease for commit or rollback.
    pub(crate) const fn applier_mut(&mut self) -> Option<&mut Applier> {
        self.applier.as_mut()
    }

    /// Releases the write lease while retaining the terminal report.
    pub(crate) fn close(&mut self) {
        if let Some(applier) = self.applier.take() {
            self.applied = Some(applier.report().clone());
            drop(applier);
        }
    }

    /// Target router used to isolate otherwise identical planner ids.
    pub(crate) const fn target(&self) -> &RouterId {
        &self.target
    }

    /// The router-qualified id, the record's key.
    pub(crate) fn key(&self) -> &str {
        &self.id
    }

    /// Whether the record holds the target's write lease.
    pub(crate) const fn leased(&self) -> bool {
        self.applier.is_some()
    }

    /// How long the router's recovery timer still runs, while the lease is held.
    pub(crate) fn recovery_left(&self) -> Option<Duration> {
        self.applier.as_ref().map(Applier::recovery_left)
    }

    /// Plan counts and the apply outcome, without command text.
    pub(crate) fn summary(&self) -> Value {
        let apply = self
            .applier
            .as_ref()
            .map(Applier::report)
            .or(self.applied.as_ref())
            .map(|report| {
                json!({
                    "job_id": self.job,
                    "applied": report.applied.len(),
                    "failed": report.failed,
                    "residual_count": report.residual_count,
                    "verified": report.verified,
                    "finished": report.finished,
                    "failure": report.failure
                })
            });
        json!({
            "plan_id": self.id,
            "source": self.source.as_str(),
            "target": self.target.as_str(),
            "counts": self.report.counts,
            "target_not_clean": self.report.target_not_clean,
            "residual_count": self.report.residual.len(),
            "apply": apply
        })
    }

    /// One page of redacted plan items.
    pub(crate) fn items(&self, offset: usize, limit: usize) -> Value {
        let items = self
            .report
            .items
            .iter()
            .skip(offset)
            .take(limit)
            .map(|item| {
                json!({
                    "source_index": self.kept.get(item.source_index).copied(),
                    "disposition": item.disposition,
                    "before": item.before,
                    "after": item.after,
                    "reason": item.reason
                })
            })
            .collect::<Vec<_>>();
        let next = offset.saturating_add(limit);
        json!({
            "items": items,
            "next_cursor": (next < self.report.items.len()).then(|| next.to_string())
        })
    }
}
