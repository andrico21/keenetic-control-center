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
    /// The router accepted the rollback and is restarting with its saved configuration.
    RollbackRestarting,
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
            Self::RollbackRestarting => keys::MIGRATE_ROLLBACK_SAVED,
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

/// The sentence explaining `failure` on the wizard's pages: the wizard's own where it
/// names the step to revisit, else the sentence every surface shows.
pub(crate) const fn failure_text(failure: ApplyError) -> MessageKey {
    match failure {
        ApplyError::Drift => keys::WEB_MIGRATE_FAILURE_DRIFT,
        ApplyError::SameRouter => keys::WEB_MIGRATE_FAILURE_SAME,
        ApplyError::Source => keys::WEB_MIGRATE_FAILURE_SOURCE,
        ApplyError::PasswordRequired => keys::WEB_MIGRATE_FAILURE_INPUT,
        ApplyError::Validation => keys::WEB_MIGRATE_FAILURE_VALIDATION,
        ApplyError::Stopped => keys::WEB_MIGRATE_FAILURE_STOPPED,
        ApplyError::Verification => keys::WEB_MIGRATE_FAILURE_VERIFICATION,
        ApplyError::Unreachable => keys::WEB_MIGRATE_FAILURE_UNREACHABLE,
        ApplyError::Cancelled => keys::WEB_MIGRATE_FAILURE_CANCELLED,
        other @ (ApplyError::ReplanRequired
        | ApplyError::UnverifiedFirmwareTier
        | ApplyError::Firmware
        | ApplyError::ModeUnknown
        | ApplyError::AgreementRequired
        | ApplyError::Workflow
        | ApplyError::DisarmFailed
        | ApplyError::SavedDisarmFailed
        | ApplyError::ArmUnconfirmed
        | ApplyError::FinishFailed
        | ApplyError::RollbackRestarting
        | ApplyError::CommittedSaveFailed
        | ApplyError::RolledBackByRouter
        | ApplyError::Job
        | ApplyError::JobStart
        | ApplyError::HardwareMismatch
        | _) => other.message_key(),
    }
}

/// The sentence explaining the failure a record names `name`; a name this kcc does not
/// know reads as a stopped migration.
pub(super) fn recorded_text(name: &str) -> MessageKey {
    ApplyError::from_name(name).map_or(keys::MIGRATE_APPLY_FAILED, failure_text)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::keys;
    use kcc_migrate::apply::ApplyError;

    use super::{Ended, Run, failure_name, recorded_text};

    /// A record written by an earlier kcc, with a failure name of today or one kcc no
    /// longer knows, loads and explains its failure.
    #[test]
    fn earlier_records_load_and_explain_their_failure() -> Result<(), serde_json::Error> {
        for (name, key) in [
            (
                failure_name(ApplyError::ReplanRequired),
                keys::MIGRATE_APPLY_REPLAN,
            ),
            (
                failure_name(ApplyError::Stopped),
                keys::WEB_MIGRATE_FAILURE_STOPPED,
            ),
            (
                failure_name(ApplyError::SavedDisarmFailed),
                keys::FINISH_SAVED_ARMED,
            ),
            ("RetiredFailure".to_owned(), keys::MIGRATE_APPLY_FAILED),
        ] {
            let stored = format!(
                "{{\"job\":\"j-1\",\"started_at\":1,\"safety_seconds\":600,\"ended\":\
                 {{\"at\":2,\"verified\":false,\"failure\":\"{name}\",\"applied\":0,\"failed\":0}}}}"
            );
            let run: Run = serde_json::from_str(&stored)?;
            let failure = run.ended().and_then(Ended::failure);
            assert_eq!(failure.map(recorded_text), Some(key), "{name}");
        }
        Ok(())
    }
}
