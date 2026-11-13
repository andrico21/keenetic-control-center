//! The apply of a migration as its record keeps it: the job, how it ended, and how the
//! migration finished.
//!
//! It holds counts and the engine's value-free failure names only.

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::{ApplyError, ApplyReport};
use serde::{Deserialize, Serialize};

/// The apply job of a migration (or of a preset run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    /// The job's id.
    job: String,
    /// Unix time it started.
    started_at: u64,
    /// The fail-safe timer's length, in seconds.
    safety_seconds: u64,
    /// How it ended, once it did.
    #[serde(default)]
    ended: Option<Ended>,
}

/// How an apply job ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ended {
    /// Unix time it ended.
    at: u64,
    /// Whether the read-back and health checks passed.
    verified: bool,
    /// The engine's failure name, such as `Stopped`.
    failure: Option<String>,
    /// Settings the router took.
    applied: usize,
    /// Settings the router refused.
    failed: usize,
}

/// How a migration finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Finish {
    /// The changes were saved on the router.
    Committed,
    /// kcc rolled the router back to its saved configuration.
    RolledBack,
    /// The router restored its saved configuration when its timer ran out.
    RolledBackByRouter,
    /// The apply ended without changes to finish: it failed before the first change, or
    /// kcc restarted while it ran.
    Closed,
}

impl Finish {
    /// The sentence saying how the migration finished.
    pub(super) const fn text(self) -> MessageKey {
        match self {
            Self::Committed => keys::WEB_MIGRATE_FINISH_COMMITTED,
            Self::RolledBack => keys::WEB_MIGRATE_FINISH_ROLLED_BACK,
            Self::RolledBackByRouter => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
            Self::Closed => keys::WEB_MIGRATE_FINISH_CLOSED,
        }
    }
}

impl Run {
    /// A job `job` started at `started_at` under a timer of `safety_seconds`.
    pub(crate) const fn new(job: String, started_at: u64, safety_seconds: u64) -> Self {
        Self {
            job,
            started_at,
            safety_seconds,
            ended: None,
        }
    }

    /// The job's id.
    pub(crate) fn job(&self) -> &str {
        &self.job
    }

    /// Unix time it started.
    pub(crate) const fn started_at(&self) -> u64 {
        self.started_at
    }

    /// The fail-safe timer's length, in seconds.
    pub(crate) const fn safety_seconds(&self) -> u64 {
        self.safety_seconds
    }

    /// How it ended, once it did.
    pub(crate) const fn ended(&self) -> Option<&Ended> {
        self.ended.as_ref()
    }

    /// Records how it ended at `at`: the engine's report, or the error it failed with
    /// before it made one.
    pub(crate) fn end(&mut self, at: u64, outcome: Result<&ApplyReport, ApplyError>) {
        self.ended = Some(match outcome {
            Ok(report) => Ended {
                at,
                verified: report.verified,
                failure: report.failure.map(failure_name),
                applied: report.applied.len(),
                failed: report.failed.len(),
            },
            Err(error) => Ended {
                at,
                verified: false,
                failure: Some(failure_name(error)),
                applied: 0,
                failed: 0,
            },
        });
    }
}

impl Ended {
    /// Whether the read-back and health checks passed.
    pub(crate) const fn verified(&self) -> bool {
        self.verified
    }

    /// The engine's failure name.
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// Settings the router took.
    pub(crate) const fn applied(&self) -> usize {
        self.applied
    }

    /// Settings the router refused.
    pub(crate) const fn failed(&self) -> usize {
        self.failed
    }
}

/// The stable name of `failure`, as the engine serializes it.
pub(crate) fn failure_name(failure: ApplyError) -> String {
    serde_json::to_value(failure)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "Workflow".to_owned())
}

/// The sentence explaining the failure named `name`.
pub(super) fn failure_text(name: &str) -> MessageKey {
    match name {
        "DisarmFailed" => keys::MANAGEMENT_DISARM_FAILED,
        "FinishFailed" => keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
        "ArmUnconfirmed" => keys::MANAGEMENT_NOT_SENT_ARMED,
        "ReplanRequired" => keys::WEB_MIGRATE_FAILURE_REPLAN,
        "UnverifiedFirmwareTier" => keys::MIGRATE_APPLY_TIER,
        "ModeUnknown" => keys::MANAGEMENT_MODE_UNKNOWN,
        "Drift" => keys::WEB_MIGRATE_FAILURE_DRIFT,
        "SameRouter" => keys::WEB_MIGRATE_FAILURE_SAME,
        "Source" => keys::WEB_MIGRATE_FAILURE_SOURCE,
        "AgreementRequired" => keys::MIGRATE_APPLY_AGREEMENT,
        "PasswordRequired" => keys::WEB_MIGRATE_FAILURE_INPUT,
        "Validation" => keys::WEB_MIGRATE_FAILURE_VALIDATION,
        "Stopped" => keys::WEB_MIGRATE_FAILURE_STOPPED,
        "Verification" => keys::WEB_MIGRATE_FAILURE_VERIFICATION,
        "RolledBackByRouter" => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
        "Unreachable" => keys::WEB_MIGRATE_FAILURE_UNREACHABLE,
        "RollbackRestarting" => keys::MIGRATE_ROLLBACK_SAVED,
        "Cancelled" => keys::WEB_MIGRATE_FAILURE_CANCELLED,
        "JobStart" => keys::MIGRATE_JOB_START_FAILED,
        _ => keys::MIGRATE_APPLY_FAILED,
    }
}
