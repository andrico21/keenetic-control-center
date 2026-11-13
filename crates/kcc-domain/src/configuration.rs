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
    workflow::{
        ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, LastChange,
        VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_rci::capabilities::SystemMode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx, read_show,
};

pub mod bracket;
pub mod close;
pub mod recovery;

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
        SafetyNet::CONTROL_PERMISSION,
        false,
    ),
    operation(
        "fail_safe_keep_alive",
        "system configuration fail-safe keep-alive",
        Risk::Write,
        SafetyNet::CONTROL_PERMISSION,
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
        SafetyNet::CONTROL_PERMISSION,
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
    /// Authority of explicit recovery control: a standalone timer and an explicit rollback.
    ///
    /// A timer armed around a change is authorized by that change's own permission instead.
    pub const CONTROL_PERMISSION: Permission = Permission::Destructive;

    /// Permissions required to apply and finish a migration, preset, or settings copy.
    pub const APPLY_PERMISSIONS: [Permission; 5] = [
        Permission::Read,
        Permission::Migrate,
        Permission::Write,
        Permission::Save,
        Self::CONTROL_PERMISSION,
    ];

    /// Permissions required to open and close a management bracket without saving.
    #[must_use]
    pub const fn management_permissions() -> &'static [Permission] {
        &[Self::CONTROL_PERMISSION]
    }

    /// Permissions required before an apply may contact any router.
    #[must_use]
    pub const fn apply_permissions() -> &'static [Permission] {
        &Self::APPLY_PERMISSIONS
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
        let (catalog_path, line) = match mode {
            SafetyMode::Router => (
                "system configuration fail-safe timer",
                format!("system configuration fail-safe timer reboot {seconds}"),
            ),
            SafetyMode::ScheduledReboot => ("system reboot", format!("system reboot {seconds}")),
        };
        let request = cli_request(router, catalog_path, line, permission)
            .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
    }

    /// Disarms the selected safety mechanism without saving other changes, authorized by
    /// `permission`, the permission of the change it protected.
    // NOT cancel-safe: cancelled after the CLI request is sent, the timer may already be disarmed
    // while the caller still treats it as armed.
    pub async fn disarm(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        mode: SafetyMode,
        permission: Permission,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let (catalog_path, line) = match mode {
            SafetyMode::Router => (
                "system configuration fail-safe timer",
                "no system configuration fail-safe timer",
            ),
            SafetyMode::ScheduledReboot => ("system reboot", "no system reboot"),
        };
        let request = cli_request(router, catalog_path, line.to_owned(), permission)
            .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
    }

    /// Restarts the native fail-safe countdown, authorized by `permission`, the permission
    /// of the change it protects.
    // NOT cancel-safe: cancelled after the CLI request is sent, the countdown may be restarted
    // without the caller knowing.
    pub async fn keep_alive(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        permission: Permission,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(
            router,
            "system configuration fail-safe keep-alive",
            "system configuration fail-safe keep-alive".to_owned(),
            permission,
        )
        .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
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

/// Builds a protected non-terminal CLI request.
fn cli_request(
    router: &RouterCtx,
    catalog_path: &str,
    line: String,
    permission: Permission,
) -> Result<CliChangeRequest> {
    let body = match catalog_path {
        "system configuration fail-safe timer" | "system reboot" if line.starts_with("no ") => {
            json!({"no": true})
        }
        "system configuration fail-safe timer" => {
            let interval = line
                .split_whitespace()
                .next_back()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(DomainError::InvalidResponse)?;
            json!({"action": "reboot", "interval": interval})
        }
        "system reboot" => {
            let interval = line
                .split_whitespace()
                .next_back()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(DomainError::InvalidResponse)?;
            json!({"interval": interval})
        }
        "system configuration fail-safe keep-alive" => json!({}),
        _ => return Err(DomainError::InvalidResponse),
    };
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    let verify = match catalog_path {
        "system configuration fail-safe timer" | "system configuration fail-safe keep-alive" => {
            vec![VerificationSpec::new(
                vec!["show".to_owned(), "last-change".to_owned()],
                "/fail-safe/active".to_owned(),
                json!(!line.starts_with("no ")),
            )]
        }
        "system reboot" => Vec::new(),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated)],
        verify,
        permission,
        json!({"operation": catalog_path}),
    ))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
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
