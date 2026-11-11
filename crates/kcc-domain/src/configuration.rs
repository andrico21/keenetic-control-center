//! Configuration persistence and recovery safety operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "safety operations follow the plan; async workflow bodies are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, LastChange,
        VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::{HttpMethod, Risk};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx, read_show,
};

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
    /// Authority shared by arming, disarming, extending, and rolling back recovery.
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

    /// Arms native fail-safe in router mode or scheduled reboot otherwise.
    // NOT cancel-safe: cancelled after the CLI request is sent, the fail-safe or reboot timer
    // is armed and fires while the caller believes nothing was armed.
    pub async fn arm(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        mode: SafetyMode,
        seconds: u64,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let (catalog_path, line) = match mode {
            SafetyMode::Router => (
                "system configuration fail-safe timer",
                format!("system configuration fail-safe timer reboot {seconds}"),
            ),
            SafetyMode::ScheduledReboot => ("system reboot", format!("system reboot {seconds}")),
        };
        let request = cli_request(router, catalog_path, line, Self::CONTROL_PERMISSION)
            .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
    }

    /// Disarms the selected safety mechanism without saving other changes.
    // NOT cancel-safe: cancelled after the CLI request is sent, the timer may already be disarmed
    // while the caller still treats it as armed.
    pub async fn disarm(
        changes: &mut ChangeSet,
        router: &RouterCtx,
        mode: SafetyMode,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let (catalog_path, line) = match mode {
            SafetyMode::Router => (
                "system configuration fail-safe timer",
                "no system configuration fail-safe timer",
            ),
            SafetyMode::ScheduledReboot => ("system reboot", "no system reboot"),
        };
        let request = cli_request(
            router,
            catalog_path,
            line.to_owned(),
            Self::CONTROL_PERMISSION,
        )
        .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
    }

    /// Restarts the native fail-safe countdown.
    // NOT cancel-safe: cancelled after the CLI request is sent, the countdown may be restarted
    // without the caller knowing.
    pub async fn keep_alive(
        changes: &mut ChangeSet,
        router: &RouterCtx,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(
            router,
            "system configuration fail-safe keep-alive",
            "system configuration fail-safe keep-alive".to_owned(),
            Self::CONTROL_PERMISSION,
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

    /// Rolls native fail-safe state back through protected destructive CLI execution.
    // NOT cancel-safe: cancelled after the CLI request is sent, the router may already be
    // rolling back (and rebooting) while the caller is unaware.
    pub async fn rollback(
        changes: &mut ChangeSet,
        router: &RouterCtx,
    ) -> CoreResult<CliChangeResult, WorkflowError> {
        let request = cli_request(
            router,
            "system configuration fail-safe rollback",
            "system configuration fail-safe rollback".to_owned(),
            Self::CONTROL_PERMISSION,
        )
        .map_err(|_error| WorkflowError::InvalidResponse)?;
        changes.apply_cli(request).await
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
        "system configuration fail-safe keep-alive" | "system configuration fail-safe rollback" => {
            json!({})
        }
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
        "system reboot" | "system configuration fail-safe rollback" => Vec::new(),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated)],
        verify,
        permission,
        json!({"operation": catalog_path}),
    ))
}
