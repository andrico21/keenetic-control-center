//! System identity, clock, NTP, reboot, and reset operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    reason = "domain operation names follow the plan; async operations and small planning helpers are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeRequest, ChangeSet, CliCommand as ValidatedCli, TerminalCliChangeRequest,
        TerminalCliChangeResult, VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::{HttpMethod, Risk};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    read_show,
};

/// Tolerant `show version` model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Version {
    /// Firmware title.
    pub title: Option<String>,
    /// Firmware release string.
    pub release: Option<String>,
    /// Marketing model.
    pub model: Option<String>,
    /// Hardware identifier.
    pub hw_id: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant `show system` model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SystemState {
    /// Router host name.
    pub hostname: Option<String>,
    /// Router DNS domain name.
    pub domainname: Option<String>,
    /// Uptime as reported by firmware.
    pub uptime: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant clock/date model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ClockDate {
    /// Calendar year.
    pub year: Option<u16>,
    /// Calendar month.
    pub month: Option<u8>,
    /// Calendar day.
    pub day: Option<u8>,
    /// Hour in local time.
    pub hour: Option<u8>,
    /// Minute in local time.
    pub min: Option<u8>,
    /// Second in local time.
    pub sec: Option<u8>,
    /// Timezone object.
    pub tz: Option<Value>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant NTP status model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NtpStatus {
    /// Synchronization state, when reported.
    pub status: Option<String>,
    /// Selected server, when reported.
    pub server: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant system-mode model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SystemMode {
    /// Router mode name.
    pub mode: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// System read inventory.
const READS: &[OperationDescriptor] = &[
    read_operation("version", "show version"),
    read_operation("system", "show system"),
    read_operation("clock_date", "show clock date"),
    read_operation("ntp_status", "show ntp status"),
    read_operation("system_mode", "show system mode"),
];

/// System write inventory.
const WRITES: &[OperationDescriptor] = &[
    write_operation(
        "hostname",
        "system hostname",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "domainname",
        "system domainname",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "description",
        "system description",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "timezone",
        "system clock timezone",
        Risk::Write,
        Permission::Write,
    ),
    write_operation("ntp_server", "ntp server", Risk::Write, Permission::Write),
    write_operation("ntp_master", "ntp master", Risk::Write, Permission::Write),
    write_operation(
        "ntp_sync_period",
        "ntp sync-period",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "reboot",
        "system reboot",
        Risk::Destructive,
        Permission::Destructive,
    ),
    write_operation(
        "factory_reset",
        "system configuration factory-reset",
        Risk::Destructive,
        Permission::Destructive,
    ),
];

/// System domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::System,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads `show version`.
pub async fn read_version(router: &RouterCtx) -> Result<Version> {
    read_show(&router.client, &["show", "version"]).await
}

/// Reads `show system`.
pub async fn read_system(router: &RouterCtx) -> Result<SystemState> {
    read_show(&router.client, &["show", "system"]).await
}

/// Reads `show clock date`.
pub async fn read_clock_date(router: &RouterCtx) -> Result<ClockDate> {
    read_show(&router.client, &["show", "clock", "date"]).await
}

/// Reads `show ntp status`.
pub async fn read_ntp_status(router: &RouterCtx) -> Result<NtpStatus> {
    read_show(&router.client, &["show", "ntp", "status"]).await
}

/// Reads `show system mode` when the selected catalog exposes it.
pub async fn read_system_mode(router: &RouterCtx) -> Result<SystemMode> {
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
        Vec::new(),
    )
}

/// Plans NTP master-mode configuration.
pub fn plan_ntp_master(router: &RouterCtx, enabled: bool) -> Result<ChangeOp> {
    plan_post(
        router,
        "ntp master",
        vec!["ntp"],
        json!({"master": enabled}),
        Vec::new(),
    )
}

/// Plans the NTP synchronization period.
pub fn plan_ntp_sync_period(router: &RouterCtx, seconds: u32) -> Result<ChangeOp> {
    plan_post(
        router,
        "ntp sync-period",
        vec!["ntp"],
        json!({"sync-period": seconds}),
        Vec::new(),
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
        "ntp server" | "ntp master" | "ntp sync-period" => vec!["ntp".to_owned()],
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
pub async fn reboot(
    changes: &mut ChangeSet,
    router: &RouterCtx,
) -> CoreResult<TerminalCliChangeResult, WorkflowError> {
    let request = terminal_request(router, "system reboot", "system reboot")
        .map_err(|_error| WorkflowError::InvalidResponse)?;
    changes.apply_cli_terminal(request).await
}

/// Factory-resets the router after an exact name confirmation.
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

/// Builds a read descriptor.
const fn read_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    }
}

/// Builds a write descriptor.
const fn write_operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
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
