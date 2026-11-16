//! Configuration persistence and recovery safety operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "safety operations follow the plan; async workflow bodies are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::{ops::RangeInclusive, result::Result as CoreResult};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeResult, LastChange, WorkflowError},
};
use kcc_catalog::Risk;
use kcc_rci::capabilities::SystemMode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use self::{
    apply_needs::ApplyNeeds,
    timer::{Timer, cli_request},
};
use crate::{
    DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx, read_show,
};

pub mod apply_needs;
pub mod bracket;
pub mod close;
pub mod recovery;
mod timer;

/// Tolerant fail-safe state nested in `show last-change`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct FailSafeState {
    /// Whether fail-safe is active.
    pub active: Option<bool>,
    /// Remaining seconds, when reported.
    pub remaining: Option<u64>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant `show last-change` model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct LastChangeState {
    /// Running configuration checksum.
    pub checksum: Option<String>,
    /// Whether running differs from startup.
    pub unsaved: Option<bool>,
    /// Last-changing agent.
    pub agent: Option<String>,
    /// Last-changing user.
    pub user: Option<String>,
    /// Fail-safe state.
    #[serde(rename = "fail-safe")]
    pub fail_safe: Option<FailSafeState>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// System mode used to select the safety mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SafetyMode {
    /// Router mode implements the native configuration fail-safe timer.
    Router,
    /// Other modes fall back to a scheduled reboot.
    ScheduledReboot,
}

/// Length of the recovery timer kcc arms around a management change.
pub const MANAGEMENT_SECONDS: u64 = 300;

/// Recovery timer lengths accepted for an operator-chosen timer.
pub const TIMER_RANGE: RangeInclusive<u64> = 300..=3600;

/// The router reports neither a system mode kcc knows nor a fail-safe timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("the router's recovery mechanism cannot be determined")]
#[non_exhaustive]
pub struct ModeUnknown;

impl SafetyMode {
    /// Chooses the recovery mechanism from a detected system mode and the baseline
    /// `show last-change`.
    ///
    /// A router that reports no mode uses the fail-safe timer only when its last-change state
    /// carries a fail-safe object with a boolean `active` member.
    ///
    /// # Errors
    ///
    /// Returns [`ModeUnknown`] for a mode kcc does not know, or an unreported mode without a
    /// fail-safe timer.
    #[inline]
    pub fn decide(
        mode: Option<&SystemMode>,
        baseline: &LastChange,
    ) -> CoreResult<Self, ModeUnknown> {
        match mode {
            Some(SystemMode::Router) => Ok(Self::Router),
            Some(SystemMode::Extender | SystemMode::Ap | SystemMode::Repeater) => {
                Ok(Self::ScheduledReboot)
            }
            None if baseline
                .fail_safe
                .get("active")
                .is_some_and(Value::is_boolean) =>
            {
                Ok(Self::Router)
            }
            Some(_) | None => Err(ModeUnknown),
        }
    }

    /// Chooses the recovery mechanism from the facts a change set captured when it began.
    ///
    /// # Errors
    ///
    /// Returns [`ModeUnknown`] under the rules of [`Self::decide`].
    #[inline]
    pub fn for_change(changes: &ChangeSet) -> CoreResult<Self, ModeUnknown> {
        Self::decide(changes.system_mode(), changes.baseline())
    }
}

/// Configuration safety operations.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SafetyNet;

/// Configuration read inventory.
const READS: &[OperationDescriptor] = &[OperationDescriptor {
    name: "last_change",
    catalog_path: "show last-change",
    risk: Risk::Read,
    permission: Permission::Read,
    persists_immediately: false,
}];

/// Configuration write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation(
        "save",
        "system configuration save",
        Risk::Write,
        Permission::Save,
        true,
    ),
    operation(
        "fail_safe_arm",
        "system configuration fail-safe timer",
        Risk::Destructive,
        Permission::Destructive,
        false,
    ),
    operation(
        "fail_safe_keep_alive",
        "system configuration fail-safe keep-alive",
        Risk::Write,
        Permission::Destructive,
        false,
    ),
    operation(
        "fail_safe_commit",
        "system configuration fail-safe commit",
        Risk::Write,
        Permission::Save,
        true,
    ),
    operation(
        "fail_safe_rollback",
        "system configuration fail-safe rollback",
        Risk::Destructive,
        Permission::Destructive,
        false,
    ),
];

/// Configuration domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Configuration,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

impl SafetyNet {
    /// Authority of an explicit, user-chosen rollback.
    ///
    /// A timer armed, kept alive or disarmed around a change is authorized by that change's
    /// own permission instead.
    pub const CONTROL_PERMISSION: Permission = Permission::Destructive;

    /// Permissions a migration, preset, or settings copy needs before it contacts any
    /// router: `Read`, `Migrate`, `Write` and `Save` for the run and its keep or save
    /// finish, plus `Destructive` when `needs` names a step that reboots or rolls back.
    #[must_use]
    pub fn apply_permissions(needs: ApplyNeeds) -> Vec<Permission> {
        let mut permissions = vec![
            Permission::Read,
            Permission::Migrate,
            Permission::Write,
            Permission::Save,
        ];
        if needs.destructive() {
            permissions.push(Permission::Destructive);
        }
        permissions
    }

    /// Permissions a change needs: its own `permission`, plus [`Permission::Destructive`] for
    /// a destructive risk. The recovery timer kcc arms around a management change needs
    /// nothing more than the change itself.
    #[must_use]
    pub fn required(permission: Permission, risk: Risk) -> Vec<Permission> {
        let mut required = vec![permission];
        if risk >= Risk::Destructive && permission != Permission::Destructive {
            required.push(Permission::Destructive);
        }
        required
    }

    /// Arms native fail-safe in router mode or scheduled reboot otherwise, authorized by
    /// `permission`, the permission of the change it protects.
    // NOT cancel-safe: cancelled after the CLI request is sent, the fail-safe or reboot timer
    // is armed and fires while the caller believes nothing was armed.
    pub async fn arm(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        mode: SafetyMode,
        seconds: u64,
        permission: Permission,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(router, Timer::Arm { mode, seconds }, permission)?;
        changes.apply_cli(request).await
    }

    /// Disarms the selected safety mechanism without saving other changes, authorized by
    /// `permission`, the permission of the change it protected. It skips the conflict check
    /// and the backup of a configuration change ([`ChangeSet::apply_recovery`]), so that no
    /// local refusal keeps the timer running.
    // NOT cancel-safe: cancelled after the CLI request is sent, the timer may already be disarmed
    // while the caller still treats it as armed.
    pub async fn disarm(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        mode: SafetyMode,
        permission: Permission,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(router, Timer::Disarm(mode), permission)?;
        changes.apply_recovery(request).await
    }

    /// Restarts the native fail-safe countdown, authorized by `permission`, the permission
    /// of the change it protects; like [`Self::disarm`], without the conflict check and the
    /// backup.
    // NOT cancel-safe: cancelled after the CLI request is sent, the countdown may be restarted
    // without the caller knowing.
    pub async fn keep_alive(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        permission: Permission,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(router, Timer::KeepAlive, permission)?;
        changes.apply_recovery(request).await
    }

    /// Explicitly persists all unsaved work after the workflow's last-change re-check.
    // NOT cancel-safe: cancelled after the commit command is sent, the configuration may be
    // persisted and the fail-safe resolved while the caller still treats the change as unsaved.
    pub async fn commit(changes: &mut ChangeSet) -> CoreResult<(), WorkflowError> {
        changes.commit().await
    }
}

/// Reads `show last-change`, including its fail-safe object.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_last_change(router: &RouterCtx) -> Result<LastChangeState> {
    read_show(&router.client, &["show", "last-change"]).await
}

/// Explicitly saves running configuration.
// NOT cancel-safe: cancelled after the save command is sent, the running configuration may be
// persisted while the caller still treats it as unsaved.
pub async fn save(changes: &mut ChangeSet) -> CoreResult<(), WorkflowError> {
    changes.save().await
}

/// Converts the typed last-change model into the workflow identity when complete.
pub fn workflow_last_change(state: &LastChangeState) -> Result<LastChange> {
    Ok(LastChange::new(
        state.checksum.clone().ok_or(DomainError::InvalidResponse)?,
        state.agent.clone().unwrap_or_default(),
        state.user.clone().unwrap_or_default(),
        state.unsaved.unwrap_or(false),
        serde_json::to_value(state.fail_safe.as_ref())
            .map_err(|_error| DomainError::InvalidResponse)?,
    ))
}

/// Builds a configuration operation descriptor.
const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
    persists_immediately: bool,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::*;

    fn baseline(fail_safe: Value) -> LastChange {
        LastChange::new(
            String::new(),
            String::new(),
            String::new(),
            false,
            fail_safe,
        )
    }

    #[test]
    fn decide_follows_the_recovery_table() {
        let timer = baseline(json!({"active": false}));
        let none = baseline(json!({}));
        let other = SystemMode::Other("bridge".to_owned());
        let rows = [
            (Some(SystemMode::Router), &none, Ok(SafetyMode::Router)),
            (
                Some(SystemMode::Extender),
                &timer,
                Ok(SafetyMode::ScheduledReboot),
            ),
            (
                Some(SystemMode::Ap),
                &timer,
                Ok(SafetyMode::ScheduledReboot),
            ),
            (
                Some(SystemMode::Repeater),
                &none,
                Ok(SafetyMode::ScheduledReboot),
            ),
            (Some(other), &timer, Err(ModeUnknown)),
            (None, &timer, Ok(SafetyMode::Router)),
            (None, &none, Err(ModeUnknown)),
            (None, &baseline(json!({"active": "yes"})), Err(ModeUnknown)),
        ];
        for (mode, baseline, expected) in rows {
            assert_eq!(SafetyMode::decide(mode.as_ref(), baseline), expected);
        }
    }
}
