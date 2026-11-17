//! The requests that arm, disarm and keep alive the recovery timer, built from typed values.

use alloc::vec;
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec, WorkflowError},
};
use kcc_catalog::HttpMethod;
use serde_json::{Value, json};

use super::SafetyMode;
use crate::RouterCtx;

/// One step on the recovery timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    variant_size_differences,
    reason = "a step is built once per request and never stored, so its size does not matter"
)]
pub(super) enum Timer {
    /// Arms `mode`'s timer to fire after `seconds`.
    Arm {
        /// The mechanism armed.
        mode: SafetyMode,
        /// Seconds before it fires.
        seconds: u64,
    },
    /// Disarms `mode`'s timer.
    Disarm(SafetyMode),
    /// Restarts the native fail-safe countdown.
    KeepAlive,
}

impl Timer {
    /// The catalog path, CLI line and request body of the step.
    fn command(self) -> (&'static str, String, Value) {
        match self {
            Self::Arm {
                mode: SafetyMode::Router,
                seconds,
            } => (
                FAIL_SAFE_TIMER,
                format!("{FAIL_SAFE_TIMER} reboot {seconds}"),
                json!({"action": "reboot", "interval": seconds}),
            ),
            Self::Arm {
                mode: SafetyMode::ScheduledReboot,
                seconds,
            } => (
                SYSTEM_REBOOT,
                format!("{SYSTEM_REBOOT} {seconds}"),
                json!({"interval": seconds}),
            ),
            Self::Disarm(SafetyMode::Router) => (
                FAIL_SAFE_TIMER,
                format!("no {FAIL_SAFE_TIMER}"),
                json!({"no": true}),
            ),
            Self::Disarm(SafetyMode::ScheduledReboot) => (
                SYSTEM_REBOOT,
                format!("no {SYSTEM_REBOOT}"),
                json!({"no": true}),
            ),
            Self::KeepAlive => (
                FAIL_SAFE_KEEP_ALIVE,
                FAIL_SAFE_KEEP_ALIVE.to_owned(),
                json!({}),
            ),
        }
    }

    /// The read-back of the step: the native timer's state; a scheduled reboot has none.
    fn verify(self) -> Vec<VerificationSpec> {
        let active = match self {
            Self::Arm {
                mode: SafetyMode::Router,
                seconds: _,
            }
            | Self::KeepAlive => true,
            Self::Disarm(SafetyMode::Router) => false,
            Self::Arm {
                mode: SafetyMode::ScheduledReboot,
                seconds: _,
            }
            | Self::Disarm(SafetyMode::ScheduledReboot) => return Vec::new(),
        };
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "last-change".to_owned()],
            "/fail-safe/active".to_owned(),
            json!(active),
        )]
    }
}

/// Catalog path and CLI words of the native fail-safe timer.
const FAIL_SAFE_TIMER: &str = "system configuration fail-safe timer";
/// Catalog path and CLI words of the native fail-safe keep-alive.
const FAIL_SAFE_KEEP_ALIVE: &str = "system configuration fail-safe keep-alive";
/// Catalog path and CLI words of a scheduled reboot.
const SYSTEM_REBOOT: &str = "system reboot";

/// Builds the protected non-terminal CLI request of one recovery timer step.
///
/// # Errors
///
/// Returns an error when the catalog refuses a request
/// ([`WorkflowError::CatalogValidation`]).
pub(super) fn cli_request(
    router: &RouterCtx,
    timer: Timer,
    permission: Permission,
) -> CoreResult<CliChangeRequest, WorkflowError> {
    let (catalog_path, line, body) = timer.command();
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, &body)
        .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated)?],
        timer.verify(),
        permission,
        json!({"operation": catalog_path}),
    ))
}
