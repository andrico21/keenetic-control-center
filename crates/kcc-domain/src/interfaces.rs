//! Interface inventory and guarded connectivity changes.

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliChangeResult, CliCommand as ValidatedCli, VerificationSpec,
    },
};
use kcc_catalog::Risk;
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, decode, descriptor, planning::validate, pointer, read_show,
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
    descriptor::read("list", "show interface"),
    descriptor::read("get", "show interface"),
    descriptor::read("statistics", "show interface stat"),
    descriptor::read("traffic_history", "show interface rrd"),
];

/// Interface write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::operation("up", "interface up", Risk::Write, Permission::Write),
    descriptor::operation(
        "down",
        "interface down",
        Risk::Management,
        Permission::Write,
    ),
    descriptor::operation(
        "description",
        "interface description",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "security_level",
        "interface security-level",
        Risk::Management,
        Permission::Write,
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
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "the read is named after the router list it returns, like the reads of the other domain modules"
)]
pub async fn read_interfaces(router: &RouterCtx) -> Result<BTreeMap<String, Interface>> {
    read_show(&router.client, &["show", "interface"]).await
}

/// Reads one interface through root POST, keeping slash-containing names out of URL paths.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_interface(router: &RouterCtx, name: &ObjectName) -> Result<Interface> {
    let answer: Value = decode::body(
        router.client.log_id(),
        "show interface",
        &router.client.show_interface(name).await?,
    )?;
    let selected = answer
        .pointer("/show/interface")
        .ok_or(DomainError::InvalidResponse)?;
    decode::value(router.client.log_id(), "show interface", selected)
}

/// Reads counters for all interfaces.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_statistics(router: &RouterCtx) -> Result<BTreeMap<String, InterfaceStatistics>> {
    read_show(&router.client, &["show", "interface", "stat"]).await
}

/// Reads an interface traffic-history resource when the router exposes it.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_traffic_history(router: &RouterCtx) -> Result<TrafficHistory> {
    read_show(&router.client, &["show", "interface", "rrd"]).await
}

/// Plans enabling an interface.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_up(router: &RouterCtx, name: &ObjectName) -> Result<ChangeOp> {
    plan_state(router, name, true, ManagementVerdict::NotManagement)
}

/// Detects whether an interface carries the management connection.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] when a router request fails, and [`DomainError::InvalidResponse`]
/// when the interface list or the bridge membership reply does not decode, or a bridge name is not
/// a valid object name.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, only read requests; cancellation changes nothing on the router.
#[inline]
pub async fn detect_management(router: &RouterCtx, name: &ObjectName) -> Result<ManagementVerdict> {
    management::detect(router, name).await
}

/// Plans disabling an interface using an explicit management verdict.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_down(
    router: &RouterCtx,
    name: &ObjectName,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    plan_state(router, name, false, verdict)
}

/// Plans an interface description change.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_description(
    router: &RouterCtx,
    name: &ObjectName,
    description: &str,
) -> Result<ChangeOp> {
    plan_interface(
        router,
        name,
        "interface description",
        &json!({"description": description}),
        "/description",
        Value::String(description.to_owned()),
        Risk::Write,
    )
}

/// Plans an interface security-zone change.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
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
        &json!({level.as_str(): true}),
        "/security-level",
        Value::String(level.as_str().to_owned()),
        verdict.risk(),
    )
}

/// Executes an interface plan through the change workflow, which reads it back.
///
/// The caller confirms a management change and runs it inside its recovery bracket
/// (`configuration::bracket::guarded`), as for every other management change.
///
/// # Errors
///
/// Returns an error when the change workflow fails: dispatch, read-back or audit (a
/// [`kcc_app::workflow::WorkflowError`]).
// NOT cancel-safe: cancelled mid-way, the change may be applied without its read-back.
#[inline]
pub async fn apply(
    changes: &mut ChangeSet,
    name: &ObjectName,
    operation: &ChangeOp,
) -> CoreResult<CliChangeResult, InterfaceChangeError> {
    let request = change_request(name, operation)?;
    guard::apply(changes, request).await
}

/// Plans an administrative-state change.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn plan_state(
    router: &RouterCtx,
    name: &ObjectName,
    enabled: bool,
    verdict: ManagementVerdict,
) -> Result<ChangeOp> {
    let (path, expected, risk) = if enabled {
        ("interface up", Value::String("up".to_owned()), Risk::Write)
    } else {
        (
            "interface down",
            Value::String("down".to_owned()),
            verdict.risk(),
        )
    };
    plan_interface(router, name, path, &json!({}), "/state", expected, risk)
}

/// Validates one interface plan and attaches selected-interface verification.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn plan_interface(
    router: &RouterCtx,
    name: &ObjectName,
    catalog_path: &str,
    body: &Value,
    field: &str,
    expected: Value,
    risk: Risk,
) -> Result<ChangeOp> {
    let validated = validate(router, catalog_path, body)?;
    let pointer = format!("/{}{field}", pointer::escape(name.as_str()));
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
///
/// # Errors
///
/// Returns an error when the description cannot be one quoted router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the plan holds no interface request this
/// module renders ([`DomainError::InvalidResponse`]).
#[inline]
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = match validated.path.as_str() {
        "interface up" => format!("interface {name} up"),
        "interface down" => format!("interface {name} down"),
        "interface description" => {
            let description = validated
                .value()
                .get("description")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?;
            let encoded = cli_token::quoted_text(description)?;
            format!("interface {name} description {encoded}")
        }
        "interface security-level" => {
            let level = ["public", "private", "protected"]
                .into_iter()
                .find(|level| validated.value().get(*level) == Some(&Value::Bool(true)))
                .ok_or(DomainError::InvalidResponse)?;
            format!("interface {name} security-level {level}")
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())?],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path, "interface": name.as_str()}),
    ))
}
