//! Mesh member inventory and maintenance actions.

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, TerminalCliChangeResult,
        VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, descriptor, planning::validate, read_show,
};

/// Tolerant mesh member.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Member {
    /// Stable member id.
    pub id: Option<String>,
    /// Operator-visible name.
    pub name: Option<String>,
    /// Member MAC address.
    pub mac: Option<String>,
    /// Whether the member is online.
    pub online: Option<bool>,
    /// Unmodelled member fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant mesh association.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Association {
    /// Mesh member id.
    pub member: Option<String>,
    /// Associated client MAC address.
    pub mac: Option<String>,
    /// Connected interface.
    pub interface: Option<String>,
    /// Unmodelled association fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Mesh reboot failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RebootError {
    /// Confirmation did not equal the member id.
    #[error("mesh member reboot confirmation does not match member id")]
    ConfirmationMismatch,
    /// Planning failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Protected execution failed.
    #[error(transparent)]
    Workflow(WorkflowError),
}

/// Mesh read inventory.
const READS: &[OperationDescriptor] = &[
    descriptor::read("members", "show mws member"),
    descriptor::read("associations", "show mws associations"),
];

/// Mesh write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::operation("acquire", "mws acquire", Risk::Write, Permission::Write),
    descriptor::operation(
        "member_reboot",
        "mws member reboot",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::operation(
        "update_check",
        "mws member update check",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "update_start",
        "mws member update start",
        Risk::Write,
        Permission::Write,
    ),
];

/// Mesh domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Mesh,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads mesh members.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_members(router: &RouterCtx) -> Result<Vec<Member>> {
    read_show(&router.client, &["show", "mws", "member"]).await
}

/// Reads mesh associations.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_associations(router: &RouterCtx) -> Result<Vec<Association>> {
    read_show(&router.client, &["show", "mws", "associations"]).await
}

/// Plans acquisition of a mesh candidate.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_acquire(router: &RouterCtx, candidate: &str) -> Result<ChangeOp> {
    plan(router, "mws acquire", &json!({"candidate": candidate}))
}

/// Plans a member update check.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_update_check(router: &RouterCtx, member: &str) -> Result<ChangeOp> {
    plan(
        router,
        "mws member update check",
        &json!({"member": member}),
    )
}

/// Plans a member update start.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_update_start(router: &RouterCtx, member: &str) -> Result<ChangeOp> {
    plan(
        router,
        "mws member update start",
        &json!({"member": member}),
    )
}

/// Converts an ordinary mesh plan into a protected parser request.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when a reply or a plan does not have the
/// expected shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = match validated.path.as_str() {
        "mws acquire" => format!("mws acquire {}", quoted(validated.value(), "candidate")?),
        "mws member update check" => format!(
            "mws member {} update check",
            quoted(validated.value(), "member")?
        ),
        "mws member update start" => format!(
            "mws member {} update start",
            quoted(validated.value(), "member")?
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())?],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path}),
    ))
}

/// Reboots a mesh member only after exact confirmation, using terminal CLI execution.
///
/// # Errors
///
/// Returns an error when the confirmation does not match the router name
/// ([`DomainError::ConfirmationMismatch`]), when an argument cannot be one safe router CLI
/// word ([`DomainError::InvalidCliToken`]), when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when the change workflow fails: dispatch, read-back
/// or audit ([`DomainError::Workflow`]).
// NOT cancel-safe: cancelled after the CLI request is sent, the member may already be rebooting
// and the reboot is unaudited.
#[inline]
pub async fn reboot_member(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    member: &str,
    confirm_text: &str,
) -> CoreResult<TerminalCliChangeResult, RebootError> {
    if confirm_text != member {
        return Err(RebootError::ConfirmationMismatch);
    }
    let body = json!({"member": member});
    let validated = validate(router, "mws member reboot", &body)?;
    let request = CliChangeRequest::terminal(
        vec![
            ValidatedCli::new(
                format!("mws member {} reboot", quoted(&body, "member")?),
                validated,
            )
            .map_err(DomainError::from)?,
        ],
        Permission::Destructive,
        json!({"operation":"mws member reboot","member":member}),
    );
    changes
        .apply_cli(request)
        .await
        .map(TerminalCliChangeResult::from)
        .map_err(RebootError::Workflow)
}

/// Validates an ordinary mesh action.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
fn plan(router: &RouterCtx, path: &str, body: &Value) -> Result<ChangeOp> {
    let validated = validate(router, path, body)?;
    Ok(ChangeOp::new(
        vec![validated],
        if path == "mws acquire" {
            vec![VerificationSpec::collection(
                vec!["show".to_owned(), "mws".to_owned(), "member".to_owned()],
                String::new(),
                json!({"id":body.get("candidate").ok_or(DomainError::InvalidResponse)?}),
                true,
            )]
        } else {
            Vec::new()
        },
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Quotes one string field for the CLI parser.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when a reply or a plan does not have the
/// expected shape ([`DomainError::InvalidResponse`]).
fn quoted(value: &Value, field: &str) -> Result<String> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    cli_token::quoted(text)
}
