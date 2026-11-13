//! The value-free migration failures and what each one means on every surface.

use kcc_domain::configuration::bracket::ArmedFate;
use kcc_i18n::{bundle::MessageKey, keys};
use serde::{
    Deserialize, Serialize,
    de::{IntoDeserializer, value},
};
use thiserror::Error;

/// Value-free migration failures; front ends localize these stable categories.
///
/// The serialized variant name is a stable contract: job records, wizard and preset
/// records, CLI `--json` output and MCP results keep it. New variants only add names.
#[derive(Clone, Copy, Debug, Deserialize, Error, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ApplyError {
    /// Components changed the inventory; the caller must collect and review a fresh plan.
    #[error("migration inventory changed; review a new plan")]
    ReplanRequired,
    /// Firmware acknowledgement is absent.
    #[error("unverified firmware tier")]
    UnverifiedFirmwareTier,
    /// Reviewed fingerprints no longer match.
    #[error("migration plan drift")]
    Drift,
    /// Source and target have the same origin.
    #[error("source and target origins collide")]
    SameRouter,
    /// Authentication or source acquisition failed.
    #[error("migration source unavailable")]
    Source,
    /// Target firmware is too old or unknown.
    #[error("incompatible target firmware")]
    Firmware,
    /// The target reports neither a system mode kcc knows nor a fail-safe timer; nothing was sent.
    #[error("target recovery mechanism unknown")]
    ModeUnknown,
    /// Agreements require confirmation of their current text.
    #[error("router agreement confirmation required")]
    AgreementRequired,
    /// Required operator password is missing.
    #[error("router password required")]
    PasswordRequired,
    /// An option or command failed boundary validation.
    #[error("invalid migration input")]
    Validation,
    /// Protected workflow refused the operation.
    #[error("migration workflow failed")]
    Workflow,
    /// Verified work remains applied but its recovery timer could not be disarmed.
    #[error("migration recovery timer remains armed")]
    DisarmFailed,
    /// Configuration was saved, but recovery disarm could not be confirmed.
    #[error("migration configuration saved; recovery timer remains armed")]
    SavedDisarmFailed,
    /// Arming was not confirmed and its cleanup failed: nothing was sent, but recovery may be armed.
    #[error("the change was not sent; the recovery timer may be armed")]
    ArmUnconfirmed,
    /// Closing could not be confirmed, so recovery must still be treated as armed.
    #[error("migration closing outcome unknown; recovery timer remains armed")]
    FinishFailed,
    /// The rollback request was accepted, but the restarting router did not return in time.
    #[error("migration rollback sent; target restarting")]
    RollbackRestarting,
    /// The live configuration was committed, but saving startup configuration failed.
    #[error("migration committed but was not saved")]
    CommittedSaveFailed,
    /// A router line failed under the selected stop policy.
    #[error("migration stopped on command error")]
    Stopped,
    /// Read-back or health checks failed.
    #[error("migration verification failed")]
    Verification,
    /// Router recovery restored the original startup state after timer expiry.
    #[error("migration rolled back by router")]
    RolledBackByRouter,
    /// Router did not return within the recovery bound.
    #[error("migration target unreachable")]
    Unreachable,
    /// The caller cancelled the job.
    #[error("migration cancelled")]
    Cancelled,
    /// Job admission failed.
    #[error("migration job unavailable")]
    Job,
    /// A shared-state identifier collision refused admission before router contact.
    #[error("migration job could not be started; retry")]
    JobStart,
    /// Hardware identity differs for raw restore.
    #[error("raw restore hardware mismatch")]
    HardwareMismatch,
}

impl ApplyError {
    /// Whether a failed finish leaves recovery armed or its disarm unconfirmed.
    #[inline]
    #[must_use]
    pub const fn recovery_armed(self) -> bool {
        self.fate().is_some()
    }

    /// What the failure left on the router when the recovery timer may still be armed;
    /// `None` when the timer is off or was never armed.
    #[inline]
    #[must_use]
    pub const fn fate(self) -> Option<ArmedFate> {
        match self {
            Self::DisarmFailed => Some(ArmedFate::Applied),
            Self::SavedDisarmFailed => Some(ArmedFate::Saved),
            Self::ArmUnconfirmed => Some(ArmedFate::NotSent),
            Self::FinishFailed => Some(ArmedFate::Unknown),
            Self::ReplanRequired
            | Self::UnverifiedFirmwareTier
            | Self::Drift
            | Self::SameRouter
            | Self::Source
            | Self::Firmware
            | Self::ModeUnknown
            | Self::AgreementRequired
            | Self::PasswordRequired
            | Self::Validation
            | Self::Workflow
            | Self::RollbackRestarting
            | Self::CommittedSaveFailed
            | Self::Stopped
            | Self::Verification
            | Self::RolledBackByRouter
            | Self::Unreachable
            | Self::Cancelled
            | Self::Job
            | Self::JobStart
            | Self::HardwareMismatch => None,
        }
    }

    /// The sentence every surface shows for this failure.
    #[inline]
    #[must_use]
    pub const fn message_key(self) -> MessageKey {
        match self {
            Self::DisarmFailed => ArmedFate::Applied.message_key(),
            Self::SavedDisarmFailed => ArmedFate::Saved.message_key(),
            Self::ArmUnconfirmed => ArmedFate::NotSent.message_key(),
            Self::FinishFailed => ArmedFate::Unknown.message_key(),
            Self::ReplanRequired => keys::MIGRATE_APPLY_REPLAN,
            Self::Drift => keys::CLI_PLAN_CHANGED,
            Self::UnverifiedFirmwareTier => keys::MIGRATE_APPLY_TIER,
            Self::ModeUnknown => keys::MANAGEMENT_MODE_UNKNOWN,
            Self::AgreementRequired => keys::MIGRATE_APPLY_AGREEMENT,
            Self::RollbackRestarting => keys::MIGRATE_ROLLBACK_SAVED,
            Self::CommittedSaveFailed => keys::MIGRATE_COMMITTED_NOT_SAVED,
            Self::RolledBackByRouter => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
            Self::JobStart => keys::MIGRATE_JOB_START_FAILED,
            Self::SameRouter
            | Self::Source
            | Self::Firmware
            | Self::PasswordRequired
            | Self::Validation
            | Self::Workflow
            | Self::Stopped
            | Self::Verification
            | Self::Unreachable
            | Self::Cancelled
            | Self::Job
            | Self::HardwareMismatch => keys::MIGRATE_APPLY_FAILED,
        }
    }

    /// The failure whose serialized name is `name`; `None` for a name no variant
    /// carries, such as one an older or newer kcc wrote.
    #[inline]
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::deserialize(IntoDeserializer::<value::Error>::into_deserializer(name)).ok()
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_domain::configuration::bracket::ArmedFate;
    use kcc_i18n::{bundle::MessageKey, keys};

    use super::ApplyError;

    /// Every variant with the message and recovery fate every surface reports for it.
    const ROWS: [(ApplyError, MessageKey, Option<ArmedFate>); 25] = [
        (ApplyError::ReplanRequired, keys::MIGRATE_APPLY_REPLAN, None),
        (
            ApplyError::UnverifiedFirmwareTier,
            keys::MIGRATE_APPLY_TIER,
            None,
        ),
        (ApplyError::Drift, keys::CLI_PLAN_CHANGED, None),
        (ApplyError::SameRouter, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Source, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Firmware, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::ModeUnknown, keys::MANAGEMENT_MODE_UNKNOWN, None),
        (
            ApplyError::AgreementRequired,
            keys::MIGRATE_APPLY_AGREEMENT,
            None,
        ),
        (
            ApplyError::PasswordRequired,
            keys::MIGRATE_APPLY_FAILED,
            None,
        ),
        (ApplyError::Validation, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Workflow, keys::MIGRATE_APPLY_FAILED, None),
        (
            ApplyError::DisarmFailed,
            keys::MANAGEMENT_DISARM_FAILED,
            Some(ArmedFate::Applied),
        ),
        (
            ApplyError::SavedDisarmFailed,
            keys::FINISH_SAVED_ARMED,
            Some(ArmedFate::Saved),
        ),
        (
            ApplyError::ArmUnconfirmed,
            keys::MANAGEMENT_NOT_SENT_ARMED,
            Some(ArmedFate::NotSent),
        ),
        (
            ApplyError::FinishFailed,
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            Some(ArmedFate::Unknown),
        ),
        (
            ApplyError::RollbackRestarting,
            keys::MIGRATE_ROLLBACK_SAVED,
            None,
        ),
        (
            ApplyError::CommittedSaveFailed,
            keys::MIGRATE_COMMITTED_NOT_SAVED,
            None,
        ),
        (ApplyError::Stopped, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Verification, keys::MIGRATE_APPLY_FAILED, None),
        (
            ApplyError::RolledBackByRouter,
            keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
            None,
        ),
        (ApplyError::Unreachable, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Cancelled, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::Job, keys::MIGRATE_APPLY_FAILED, None),
        (ApplyError::JobStart, keys::MIGRATE_JOB_START_FAILED, None),
        (
            ApplyError::HardwareMismatch,
            keys::MIGRATE_APPLY_FAILED,
            None,
        ),
    ];

    /// The row of `error`; the exhaustive match makes a new variant fail to compile here.
    const fn row(error: ApplyError) -> usize {
        match error {
            ApplyError::ReplanRequired => 0,
            ApplyError::UnverifiedFirmwareTier => 1,
            ApplyError::Drift => 2,
            ApplyError::SameRouter => 3,
            ApplyError::Source => 4,
            ApplyError::Firmware => 5,
            ApplyError::ModeUnknown => 6,
            ApplyError::AgreementRequired => 7,
            ApplyError::PasswordRequired => 8,
            ApplyError::Validation => 9,
            ApplyError::Workflow => 10,
            ApplyError::DisarmFailed => 11,
            ApplyError::SavedDisarmFailed => 12,
            ApplyError::ArmUnconfirmed => 13,
            ApplyError::FinishFailed => 14,
            ApplyError::RollbackRestarting => 15,
            ApplyError::CommittedSaveFailed => 16,
            ApplyError::Stopped => 17,
            ApplyError::Verification => 18,
            ApplyError::RolledBackByRouter => 19,
            ApplyError::Unreachable => 20,
            ApplyError::Cancelled => 21,
            ApplyError::Job => 22,
            ApplyError::JobStart => 23,
            ApplyError::HardwareMismatch => 24,
        }
    }

    /// The persisted name parses back, the fate decides whether recovery is armed, and
    /// each variant has its one message.
    #[test]
    fn every_failure_has_one_name_fate_and_message() {
        for (index, (error, key, fate)) in ROWS.into_iter().enumerate() {
            assert_eq!(row(error), index, "{error:?}");
            let name = serde_json::to_value(error)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            assert_eq!(ApplyError::from_name(&name), Some(error), "{name}");
            assert_eq!(error.fate(), fate, "{error:?}");
            assert_eq!(error.recovery_armed(), fate.is_some(), "{error:?}");
            assert_eq!(error.message_key(), key, "{error:?}");
        }
    }

    /// A name no variant carries (an older or a corrupted record) is not a failure kcc
    /// knows.
    #[test]
    fn unknown_names_parse_to_nothing() {
        for name in ["", "Disarm", "disarm_failed", "ReplanRequired "] {
            assert_eq!(ApplyError::from_name(name), None, "{name:?}");
        }
    }
}
