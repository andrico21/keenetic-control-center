//! System log reading, forwarding, reduction, suppression, and clearing.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planning and asynchronous reads are not useful inline candidates"
)]

use alloc::vec;

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    diagnostics,
};

/// Logging read inventory.
const READS: &[OperationDescriptor] =
    &[operation("read", "show log", Risk::Read, Permission::Read)];

/// Logging write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation(
        "server",
        "system log server",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "reduction",
        "system log reduction",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "suppress",
        "system log suppress",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "clear",
        "system log clear",
        Risk::Destructive,
        Permission::Destructive,
    ),
];

/// Logging domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Logging,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads router log text through the todo-21 POST-aware reader.
pub async fn read_log(router: &RouterCtx, max_lines: u32) -> Result<String> {
    diagnostics::read_log(&router.client, max_lines).await
}

/// Plans adding or removing a remote log server.
pub fn plan_server(
    router: &RouterCtx,
    address: &str,
    port: Option<u16>,
    enabled: bool,
) -> Result<ChangeOp> {
    validate_token(address)?;
    let mut fields = Map::new();
    drop(fields.insert("address".to_owned(), Value::String(address.to_owned())));
    if let Some(number) = port {
        drop(fields.insert("port".to_owned(), Value::from(number)));
    }
    if !enabled {
        drop(fields.insert("no".to_owned(), Value::Bool(true)));
    }
    let body = Value::Object(fields);
    plan(
        router,
        "system log server",
        &body,
        Risk::Write,
        Permission::Write,
    )
}

/// Plans log-reduction state.
pub fn plan_reduction(router: &RouterCtx, enabled: bool) -> Result<ChangeOp> {
    let body = if enabled {
        json!({})
    } else {
        json!({"no":true})
    };
    plan(
        router,
        "system log reduction",
        &body,
        Risk::Write,
        Permission::Write,
    )
}

/// Plans adding or removing one suppressed log identifier.
pub fn plan_suppress(router: &RouterCtx, ident: &str, enabled: bool) -> Result<ChangeOp> {
    validate_token(ident)?;
    let body = if enabled {
        json!({"ident":ident})
    } else {
        json!({"ident":ident,"no":true})
    };
    plan(
        router,
        "system log suppress",
        &body,
        Risk::Write,
        Permission::Write,
    )
}

/// Plans confirmed destructive log clearing after authorization.
pub fn plan_clear(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    confirmed: bool,
) -> Result<ChangeOp> {
    authorize(role, Permission::Destructive, router_name)
        .map_err(|_error| DomainError::PermissionDenied)?;
    if !confirmed {
        return Err(DomainError::ConfirmationRequired);
    }
    plan(
        router,
        "system log clear",
        &json!({}),
        Risk::Destructive,
        Permission::Destructive,
    )
}

/// Converts a logging plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let prefix = if request.value.get("no").and_then(Value::as_bool) == Some(true) {
        "no "
    } else {
        ""
    };
    let line = match request.path.as_str() {
        "system log clear" | "system log reduction" => format!("{prefix}{}", request.path),
        "system log suppress" => format!(
            "{prefix}system log suppress {}",
            request
                .value
                .get("ident")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?
        ),
        "system log server" => {
            let address = request
                .value
                .get("address")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?;
            request
                .value
                .get("port")
                .and_then(Value::as_u64)
                .map_or_else(
                    || format!("{prefix}system log server {address}"),
                    |port| format!("{prefix}system log server {address} {port}"),
                )
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, request.clone())],
        Vec::new(),
        operation.permission,
        json!({"operation":request.path}),
    ))
}

/// Builds one operation descriptor.
const fn operation(
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

/// Plans one catalog-validated logging operation.
fn plan(
    router: &RouterCtx,
    path: &str,
    body: &Value,
    risk: Risk,
    permission: Permission,
) -> Result<ChangeOp> {
    let validated = validate(router, path, body)?;
    Ok(ChangeOp::new(
        vec![validated],
        Vec::new(),
        risk,
        permission,
        false,
    ))
}

/// Validates one catalog request.
fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

/// Rejects values that cannot be represented as one unquoted router CLI token.
fn validate_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains(['\'', '"', '\\', ';', '|'])
    {
        return Err(DomainError::InvalidCliToken);
    }
    Ok(())
}
