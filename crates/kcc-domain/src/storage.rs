//! Attached storage inventory and destructive maintenance operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planning and asynchronous reads are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
    workflow::{CliChangeRequest, CliCommand},
};
use kcc_catalog::{HttpMethod, Risk};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    read_show,
};

/// One mounted media volume.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct MediaVolume {
    /// Router media identifier.
    pub id: Option<String>,
    /// Volume label.
    pub label: Option<String>,
    /// Filesystem type.
    pub filesystem: Option<String>,
    /// Total bytes.
    pub size: Option<u64>,
    /// Free bytes.
    pub free: Option<u64>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One attached USB device.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct UsbDevice {
    /// Router USB identifier.
    pub id: Option<String>,
    /// Device vendor.
    pub vendor: Option<String>,
    /// Device product.
    pub product: Option<String>,
    /// Connection state.
    pub connected: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Destructive storage maintenance action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MaintenanceAction {
    /// Checks a partition for filesystem errors.
    Check,
    /// Formats a partition with the requested filesystem.
    Format,
}

/// Inputs required to authorize and confirm destructive storage maintenance.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct MaintenanceRequest<'input> {
    /// Router id used for scope authorization.
    pub router_name: &'input str,
    /// Caller role.
    pub role: &'input Role,
    /// Target partition identifier.
    pub partition: &'input str,
    /// Filesystem name for format, absent for check.
    pub filesystem: Option<&'input str>,
    /// Explicit destructive confirmation.
    pub confirmed: bool,
}

impl<'input> MaintenanceRequest<'input> {
    /// Creates a destructive maintenance request.
    #[inline]
    #[must_use]
    pub const fn new(
        router_name: &'input str,
        role: &'input Role,
        partition: &'input str,
        filesystem: Option<&'input str>,
        confirmed: bool,
    ) -> Self {
        Self {
            router_name,
            role,
            partition,
            filesystem,
            confirmed,
        }
    }
}

/// Storage read inventory.
const READS: &[OperationDescriptor] = &[
    operation("media", "show media", Risk::Read, Permission::Read),
    operation("usb", "show usb", Risk::Read, Permission::Read),
];

/// Storage write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation(
        "eject",
        "system eject",
        Risk::Destructive,
        Permission::Destructive,
    ),
    operation(
        "partition_check",
        "system partition check",
        Risk::Destructive,
        Permission::Destructive,
    ),
    operation(
        "partition_format",
        "system partition format",
        Risk::Destructive,
        Permission::Destructive,
    ),
];

/// Storage domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Storage,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &["usb", "storage"],
};

/// Reads mounted media volumes.
pub async fn read_media(router: &RouterCtx) -> Result<Vec<MediaVolume>> {
    read_show(&router.client, &["show", "media"]).await
}

/// Reads attached USB devices.
pub async fn read_usb(router: &RouterCtx) -> Result<Vec<UsbDevice>> {
    read_show(&router.client, &["show", "usb"]).await
}

/// Plans a confirmed destructive media eject.
pub fn plan_eject(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    media: &str,
    confirmed: bool,
) -> Result<ChangeOp> {
    authorize(role, Permission::Destructive, router_name)
        .map_err(|_error| DomainError::PermissionDenied)?;
    confirm(confirmed)?;
    validate_token(media)?;
    let validated = router
        .catalog
        .validate("system eject", HttpMethod::Post, &json!({"name":media}))
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(destructive(vec![validated]))
}

/// Plans confirmed destructive partition maintenance.
pub fn plan_maintenance(
    router: &RouterCtx,
    action: MaintenanceAction,
    request: MaintenanceRequest<'_>,
) -> Result<ChangeOp> {
    authorize(request.role, Permission::Destructive, request.router_name)
        .map_err(|_error| DomainError::PermissionDenied)?;
    confirm(request.confirmed)?;
    validate_token(request.partition)?;
    let (path, body) = match action {
        MaintenanceAction::Check => (
            "system partition check",
            json!({"partition":request.partition}),
        ),
        MaintenanceAction::Format => {
            let filesystem = request.filesystem.ok_or(DomainError::InvalidCliToken)?;
            validate_token(filesystem)?;
            (
                "system partition format",
                json!({"partition":request.partition,"filesystem":filesystem}),
            )
        }
    };
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(destructive(vec![validated]))
}

/// Converts a storage plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let line = match request.path.as_str() {
        "system eject" => format!(
            "system eject {}",
            request
                .value
                .get("name")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?
        ),
        "system partition check" => format!(
            "system partition {} check",
            request
                .value
                .get("partition")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?
        ),
        "system partition format" => format!(
            "system partition {} format {}",
            request
                .value
                .get("partition")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?,
            request
                .value
                .get("filesystem")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![CliCommand::new(line, request.clone())],
        Vec::new(),
        Permission::Destructive,
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

/// Builds the shared destructive operation shape.
const fn destructive(requests: Vec<kcc_catalog::ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Destructive,
        Permission::Destructive,
        false,
    )
}

/// Requires explicit confirmation before catalog or router work.
const fn confirm(confirmed: bool) -> Result<()> {
    if confirmed {
        Ok(())
    } else {
        Err(DomainError::ConfirmationRequired)
    }
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
