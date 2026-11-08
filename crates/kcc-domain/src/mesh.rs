//! Mesh member inventory and maintenance actions.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain async actions are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, TerminalCliChangeRequest,
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
    read_operation("members", "show mws member"),
    read_operation("associations", "show mws associations"),
];

/// Mesh write inventory.
const WRITES: &[OperationDescriptor] = &[
    write_operation("acquire", "mws acquire", Risk::Write, Permission::Write),
    write_operation(
        "member_reboot",
        "mws member reboot",
        Risk::Destructive,
        Permission::Destructive,
    ),
    write_operation(
        "update_check",
        "mws member update check",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
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
pub async fn read_members(router: &RouterCtx) -> Result<Vec<Member>> {
    read_show(&router.client, &["show", "mws", "member"]).await
}

/// Reads mesh associations.
pub async fn read_associations(router: &RouterCtx) -> Result<Vec<Association>> {
    read_show(&router.client, &["show", "mws", "associations"]).await
}

/// Plans acquisition of a mesh candidate.
pub fn plan_acquire(router: &RouterCtx, candidate: &str) -> Result<ChangeOp> {
    plan(router, "mws acquire", &json!({"candidate": candidate}))
}

/// Plans a member update check.
pub fn plan_update_check(router: &RouterCtx, member: &str) -> Result<ChangeOp> {
    plan(
        router,
        "mws member update check",
        &json!({"member": member}),
    )
}

/// Plans a member update start.
pub fn plan_update_start(router: &RouterCtx, member: &str) -> Result<ChangeOp> {
    plan(
        router,
        "mws member update start",
        &json!({"member": member}),
    )
}

/// Converts an ordinary mesh plan into a protected parser request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let validated = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = match validated.path.as_str() {
        "mws acquire" => format!("mws acquire {}", quoted(&validated.value, "candidate")?),
        "mws member update check" => format!(
            "mws member {} update check",
            quoted(&validated.value, "member")?
        ),
        "mws member update start" => format!(
            "mws member {} update start",
            quoted(&validated.value, "member")?
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, validated.clone())],
        operation.verify.clone(),
        operation.permission,
        json!({"operation": validated.path}),
    ))
}

/// Reboots a mesh member only after exact confirmation, using terminal CLI execution.
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
    let validated = router
        .catalog
        .validate("mws member reboot", HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    let request = TerminalCliChangeRequest::new(
        vec![ValidatedCli::new(
            format!("mws member {} reboot", quoted(&body, "member")?),
            validated,
        )],
        Permission::Destructive,
        json!({"operation":"mws member reboot","member":member}),
    );
    changes
        .apply_cli_terminal(request)
        .await
        .map_err(RebootError::Workflow)
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

/// Validates an ordinary mesh action.
fn plan(router: &RouterCtx, path: &str, body: &Value) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
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
fn quoted(value: &Value, field: &str) -> Result<String> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    serde_json::to_string(text).map_err(|_error| DomainError::InvalidResponse)
}
