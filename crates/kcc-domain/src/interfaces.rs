//! Interface inventory and guarded connectivity changes.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    reason = "domain operation names follow the plan; async workflow bodies are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, VerificationSpec,
    },
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_rci::{ObjectName, RciBody};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    read_show,
};

/// Interface change execution and its read-back.
pub mod guard;
/// Management-connection detection from router and client topology.
pub mod management;
pub(crate) mod membership;
/// Tolerant interface response models.
pub mod models;

/// Tolerant interface summary returned by `show interface`.
pub type Interface = models::Interface;
/// Tolerant interface counter set.
pub type InterfaceStatistics = models::InterfaceStatistics;
/// Tolerant traffic-history response.
pub type TrafficHistory = models::TrafficHistory;

/// Interface security zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecurityLevel {
    /// Internet-facing zone.
    Public,
    /// Trusted local zone.
    Private,
    /// Protected zone.
    Protected,
}

/// Failures of an interface change.
pub type InterfaceChangeError = guard::InterfaceChangeError;
/// Result of management-connection detection.
pub type ManagementVerdict = management::ManagementVerdict;

/// Interface read inventory.
const READS: &[OperationDescriptor] = &[
    read_operation("list", "show interface"),
    read_operation("get", "show interface"),
    read_operation("statistics", "show interface stat"),
    read_operation("traffic_history", "show interface rrd"),
];

/// Interface write inventory.
const WRITES: &[OperationDescriptor] = &[
    write_operation("up", "interface up", Risk::Write),
    write_operation("down", "interface up", Risk::Management),
    write_operation("description", "interface description", Risk::Write),
    write_operation(
        "security_level",
        "interface security-level",
        Risk::Management,
    ),
];

/// Interface domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Interfaces,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

impl SecurityLevel {
    /// Returns the router keyword.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Protected => "protected",
        }
    }
}

/// Reads all interface summaries keyed by interface name.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_interfaces(router: &RouterCtx) -> Result<BTreeMap<String, Interface>> {
    read_show(&router.client, &["show", "interface"]).await
}

/// Reads one interface through root POST, keeping slash-containing names out of URL paths.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_interface(router: &RouterCtx, name: &ObjectName) -> Result<Interface> {
    let RciBody::Json(response) = router.client.show_interface(name).await? else {
        return Err(DomainError::InvalidResponse);
    };
    let selected = response
        .value
        .pointer("/show/interface")
        .cloned()
        .ok_or(DomainError::InvalidResponse)?;
    serde_json::from_value(selected).map_err(|_error| DomainError::InvalidResponse)
}

/// Reads counters for all interfaces.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_statistics(router: &RouterCtx) -> Result<BTreeMap<String, InterfaceStatistics>> {
    read_show(&router.client, &["show", "interface", "stat"]).await
}

/// Reads an interface traffic-history resource when the router exposes it.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_traffic_history(router: &RouterCtx) -> Result<TrafficHistory> {
    read_show(&router.client, &["show", "interface", "rrd"]).await
}

/// Plans enabling an interface.
pub fn plan_up(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan_state(router, name, true, ManagementVerdict::NotManagement)
}

/// Detects whether an interface carries the management connection.
// cancel-safe: only read requests; cancellation changes nothing on the router.
pub async fn detect_management(router: &RouterCtx, name: &ObjectName) -> Result<ManagementVerdict> {
    management::detect(router, name).await
}

/// Plans disabling an interface using an explicit management verdict.
pub fn plan_down(
    router: &RouterCtx,
    name: &ObjectName,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_state(router, name, false, verdict)
}

/// Plans an interface description change.
pub fn plan_description(
    router: &RouterCtx,
    name: &ObjectName,
    description: &str,
) -> Result<ChangeOp> {
    plan_interface(
        router,
        name,
        "interface description",
        json!({"description": description}),
        "/description",
        Value::String(description.to_owned()),
        Risk::Write,
    )
}

/// Plans an interface security-zone change.
pub fn plan_security_level(
    router: &RouterCtx,
    name: &ObjectName,
    level: SecurityLevel,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_interface(
        router,
        name,
        "interface security-level",
        json!({level.as_str(): true}),
        "/security-level",
        Value::String(level.as_str().to_owned()),
        verdict.risk(name),
    )
}

/// Executes an interface plan; a management change is read back through `show last-change`.
///
/// The caller confirms a management change and runs it inside its recovery bracket
/// (`configuration::bracket::guarded`), as for every other management change.
// NOT cancel-safe: cancelled mid-way, the change may be applied without its read-back.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    name: &ObjectName,
    operation: &ChangeOp,
) -> CoreResult<CliChangeResult, InterfaceChangeError> {
    let request = change_request(name, operation)?;
    guard::apply(changes, router, request, operation.risk).await
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
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission: Permission::Write,
        persists_immediately: false,
    }
}

/// Plans an administrative-state change.
fn plan_state(
    router: &RouterCtx,
    name: &ObjectName,
    enabled: bool,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    let (body, expected, risk) = if enabled {
        (json!({}), Value::String("up".to_owned()), Risk::Write)
    } else {
        (
            json!({"no": true}),
            Value::String("down".to_owned()),
            verdict.risk(name),
        )
    };
    plan_interface(router, name, "interface up", body, "/state", expected, risk)
}

/// Validates one interface plan and attaches selected-interface verification.
fn plan_interface(
    router: &RouterCtx,
    name: &ObjectName,
    catalog_path: &str,
    body: Value,
    field: &str,
    expected: Value,
    risk: Risk,
) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(catalog_path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    let pointer = format!(
        "/{}{field}",
        name.as_str().replace('~', "~0").replace('/', "~1")
    );
    Ok(ChangeOp::new(
        vec![validated],
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "interface".to_owned()],
            pointer,
            expected,
        )],
        risk,
        Permission::Write,
        false,
    ))
}

/// Converts a validated interface plan into its one parser request.
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = match validated.path.as_str() {
        "interface up" if validated.value.get("no") == Some(&Value::Bool(true)) => {
            format!("interface {name} down")
        }
        "interface up" => format!("interface {name} up"),
        "interface description" => {
            let description = validated
                .value
                .get("description")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?;
            let encoded = serde_json::to_string(description)
                .map_err(|_error| DomainError::InvalidResponse)?;
            format!("interface {name} description {encoded}")
        }
        "interface security-level" => {
            let level = ["public", "private", "protected"]
                .into_iter()
                .find(|level| validated.value.get(*level) == Some(&Value::Bool(true)))
                .ok_or(DomainError::InvalidResponse)?;
            format!("interface {name} security-level {level}")
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path, "interface": name.as_str()}),
    ))
}
