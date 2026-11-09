//! System identity, clock, NTP, reboot, and reset operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    reason = "domain operation names follow the plan; async operations and small planning helpers are not useful inline candidates"
)]

use alloc::vec;
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeRequest, ChangeSet, CliCommand as ValidatedCli, TerminalCliChangeRequest,
        TerminalCliChangeResult, VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::{HttpMethod, Risk, ValidationIssue};
use serde_json::{Value, json};

use crate::{ChangeOp, DomainDescriptor, DomainError, DomainId, Result, RouterCtx, read_show};

mod descriptor;
pub mod models;
/// Tolerant firmware identity.
pub type Version = models::Version;
/// Tolerant system state.
pub type SystemState = models::SystemState;
/// Tolerant clock state.
pub type ClockDate = models::ClockDate;
/// Tolerant NTP state.
pub type NtpStatus = models::NtpStatus;
/// Tolerant operating mode.
pub type SystemMode = models::SystemMode;

/// System domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::System,
    read_ops: descriptor::READS,
    write_ops: descriptor::WRITES,
    required_components: &[],
};

/// Reads `show version`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_version(router: &RouterCtx) -> Result<Version> {
    read_show(&router.client, &["show", "version"]).await
}

/// Reads `show system`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_system(router: &RouterCtx) -> Result<SystemState> {
    read_show(&router.client, &["show", "system"]).await
}

/// Reads `show clock date`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_clock_date(router: &RouterCtx) -> Result<ClockDate> {
    read_show(&router.client, &["show", "clock", "date"]).await
}

/// Reads `show ntp status`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_ntp_status(router: &RouterCtx) -> Result<NtpStatus> {
    read_show(&router.client, &["show", "ntp", "status"]).await
}

/// Reads `show system mode`; refuses before any request when the selected catalog lacks it
/// (4.3 firmware).
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_system_mode(router: &RouterCtx) -> Result<SystemMode> {
    const PATH: &str = "show system mode";
    if router.catalog.lookup(PATH).is_none() {
        return Err(DomainError::Validation {
            issues: vec![ValidationIssue::UnknownPath {
                path: PATH.to_owned(),
            }],
        });
    }
    read_show(&router.client, &["show", "system", "mode"]).await
}

/// Plans a host-name change.
pub fn plan_hostname(router: &RouterCtx, hostname: &str) -> Result<ChangeOp> {
    plan_system_field(router, "system hostname", "hostname", hostname, "/name")
}

/// Plans a domain-name change.
pub fn plan_domainname(router: &RouterCtx, domain: &str) -> Result<ChangeOp> {
    plan_system_field(router, "system domainname", "domain", domain, "/domainname")
}

/// Plans a router-description change.
pub fn plan_description(router: &RouterCtx, description: &str) -> Result<ChangeOp> {
    plan_system_field(
        router,
        "system description",
        "description",
        description,
        "/description",
    )
}

/// Plans a timezone change.
pub fn plan_timezone(router: &RouterCtx, locality: &str) -> Result<ChangeOp> {
    plan_post(
        router,
        "system clock timezone",
        vec!["system", "clock", "timezone"],
        json!({"locality": locality}),
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "clock".to_owned(), "date".to_owned()],
            "/tz/locality".to_owned(),
            Value::String(locality.to_owned()),
        )],
    )
}

/// Plans an NTP-server change.
pub fn plan_ntp_server(router: &RouterCtx, server: &str) -> Result<ChangeOp> {
    plan_post(
        router,
        "ntp server",
        vec!["ntp"],
        json!({"server": server}),
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "rc".to_owned(), "ntp".to_owned()],
            "/server".to_owned(),
            json!(server),
        )],
    )
}

/// Plans NTP master-mode configuration.
pub fn plan_ntp_master(router: &RouterCtx, enabled: bool) -> Result<ChangeOp> {
    plan_post(
        router,
        "ntp master",
        vec!["ntp"],
        if enabled {
            json!({})
        } else {
            json!({"no":true})
        },
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "rc".to_owned(), "ntp".to_owned()],
            "/master".to_owned(),
            json!(enabled),
        )],
    )
}

/// Plans the NTP synchronization period.
pub fn plan_ntp_sync_period(router: &RouterCtx, seconds: u32) -> Result<ChangeOp> {
    plan_post(
        router,
        "ntp sync-period",
        vec!["ntp"],
        json!({"period": seconds}),
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "rc".to_owned(), "ntp".to_owned()],
            "/sync-period".to_owned(),
            json!(seconds),
        )],
    )
}

/// Converts a POST plan into the protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<ChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let rci_path = match request.path.as_str() {
        "system hostname" | "system domainname" | "system description" => vec!["system".to_owned()],
        "system clock timezone" => vec![
            "system".to_owned(),
            "clock".to_owned(),
            "timezone".to_owned(),
        ],
        "ntp server" => vec!["ntp".to_owned()],
        "ntp master" => vec!["ntp".to_owned(), "master".to_owned()],
        "ntp sync-period" => vec!["ntp".to_owned(), "sync-period".to_owned()],
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(ChangeRequest::new(
        request.path.clone(),
        rci_path,
        request.value.clone(),
        operation.verify.clone(),
        operation.permission,
        json!({"operation": request.path}),
    ))
}

/// Reboots the router through the terminal workflow path.
// NOT cancel-safe: cancelled after the CLI request is sent, the router may already be rebooting
// and the reboot is unaudited.
pub async fn reboot(
    changes: &mut ChangeSet,
    router: &RouterCtx,
) -> CoreResult<TerminalCliChangeResult, WorkflowError> {
    let request = terminal_request(router, "system reboot", "system reboot")
        .map_err(|_error| WorkflowError::InvalidResponse)?;
    changes.apply_cli_terminal(request).await
}

/// Factory-resets the router after an exact name confirmation.
// NOT cancel-safe: cancelled after the CLI request is sent, the router may already be resetting
// to factory defaults and the reset is unaudited.
pub async fn factory_reset(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    router_name: &str,
    confirm_text: &str,
) -> CoreResult<TerminalCliChangeResult, FactoryResetError> {
    if confirm_text != router_name {
        return Err(FactoryResetError::ConfirmationMismatch);
    }
    let request = terminal_request(
        router,
        "system configuration factory-reset",
        "system configuration factory-reset",
    )?;
    changes
        .apply_cli_terminal(request)
        .await
        .map_err(FactoryResetError::Workflow)
}

/// Validates the factory-reset confirmation before any workflow or router access.
pub fn confirm_factory_reset(router_name: &str, confirm_text: &str) -> Result<()> {
    if confirm_text == router_name {
        Ok(())
    } else {
        Err(DomainError::ConfirmationMismatch)
    }
}

/// Factory-reset failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FactoryResetError {
    /// Confirmation did not equal the router name.
    #[error("factory reset confirmation does not match router name")]
    ConfirmationMismatch,
    /// Planning failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Protected execution failed.
    #[error(transparent)]
    Workflow(WorkflowError),
}

/// Plans one system string field.
fn plan_system_field(
    router: &RouterCtx,
    catalog_path: &str,
    argument: &str,
    value: &str,
    verify_field: &str,
) -> Result<ChangeOp> {
    plan_post(
        router,
        catalog_path,
        vec!["system"],
        json!({argument: value}),
        vec![VerificationSpec::new(
            vec!["system".to_owned()],
            verify_field.to_owned(),
            Value::String(value.to_owned()),
        )],
    )
}

/// Validates one POST plan.
fn plan_post(
    router: &RouterCtx,
    catalog_path: &str,
    _rci_path: Vec<&str>,
    body: Value,
    verify: Vec<VerificationSpec>,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ChangeOp::new(
        vec![validated],
        verify,
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Builds a destructive terminal request.
fn terminal_request(
    router: &RouterCtx,
    catalog_path: &str,
    line: &str,
) -> Result<TerminalCliChangeRequest> {
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, &json!({}))
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(TerminalCliChangeRequest::new(
        vec![ValidatedCli::new(line.to_owned(), validated)],
        Permission::Destructive,
        json!({"operation": catalog_path}),
    ))
}
