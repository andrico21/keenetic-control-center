//! Attached storage inventory and the destructive media eject and initialize.

use alloc::{collections::BTreeMap, vec};
use core::time::Duration;

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, WorkflowError},
};
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token::validate as validate_token, descriptor, planning::validate, read_show,
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

/// Storage read inventory.
const READS: &[OperationDescriptor] = &[
    descriptor::read("media", "show media"),
    descriptor::read("usb", "show usb"),
];

/// The longest [`wait_initialized`] waits for a medium to report ext4.
pub const INITIALIZE_LIMIT: Duration = Duration::from_mins(10);

/// The delay between two `show media` reads of [`wait_initialized`].
pub const INITIALIZE_POLL: Duration = Duration::from_secs(5);

/// Storage write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::operation(
        "eject",
        "system eject",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::operation(
        "initialize",
        "media initialize",
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
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_media(router: &RouterCtx) -> Result<Vec<MediaVolume>> {
    read_show(&router.client, &["show", "media"]).await
}

/// Reads attached USB devices.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_usb(router: &RouterCtx) -> Result<Vec<UsbDevice>> {
    read_show(&router.client, &["show", "usb"]).await
}

/// Plans a confirmed destructive media eject.
///
/// `entware_media` is the medium Entware runs from ([`crate::entware::configured_media`]);
/// ejecting it needs `entware_acknowledged`.
///
/// # Errors
///
/// Returns an error when the role lacks the permission or the router scope
/// ([`DomainError::PermissionDenied`]), when the destructive change is not confirmed
/// ([`DomainError::ConfirmationRequired`]), when an argument cannot be one safe router CLI
/// word ([`DomainError::InvalidCliToken`]), when the medium is the unacknowledged Entware
/// drive ([`DomainError::EntwareDriveInUse`]), or when the catalog refuses a planned
/// request ([`DomainError::Validation`]).
#[inline]
pub fn plan_eject(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    media: &str,
    confirmed: bool,
    entware_media: Option<&str>,
    entware_acknowledged: bool,
) -> Result<ChangeOp> {
    admit(
        (router_name, role, confirmed),
        media,
        (entware_media, entware_acknowledged),
    )?;
    let validated = validate(router, "system eject", &json!({"name":media}))?;
    Ok(destructive(vec![validated]))
}

/// Plans a confirmed destructive `media <media> initialize ext4`.
///
/// The router wipes the partition table and creates a swap and an ext4 partition in the
/// background (5.01 and later); [`wait_initialized`] waits for it.
///
/// `entware_media` is the medium Entware runs from ([`crate::entware::configured_media`]);
/// initializing it needs `entware_acknowledged`.
///
/// # Errors
///
/// Returns an error when the role lacks the permission or the router scope
/// ([`DomainError::PermissionDenied`]), when the destructive change is not confirmed
/// ([`DomainError::ConfirmationRequired`]), when the medium is not one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), when the medium is the unacknowledged Entware drive
/// ([`DomainError::EntwareDriveInUse`]), or when the router's catalog lacks the command or
/// refuses the request ([`DomainError::Validation`]).
#[inline]
pub fn plan_initialize(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    media: &str,
    confirmed: bool,
    entware_media: Option<&str>,
    entware_acknowledged: bool,
) -> Result<ChangeOp> {
    admit(
        (router_name, role, confirmed),
        media,
        (entware_media, entware_acknowledged),
    )?;
    let validated = validate(
        router,
        "media initialize",
        &json!({"name":media,"preset":"ext4"}),
    )?;
    Ok(destructive(vec![validated]))
}

/// Waits until `show media` reports `media` with an ext4 filesystem, reading it every
/// [`INITIALIZE_POLL`] for at most [`INITIALIZE_LIMIT`].
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), and a verification failure
/// naming the medium ([`DomainError::Workflow`]) when it does not report ext4 in time.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only; dropped, it stops polling.
#[inline]
pub async fn wait_initialized(router: &RouterCtx, media: &str) -> Result<()> {
    let polled = timeout(INITIALIZE_LIMIT, async {
        loop {
            let volumes = read_media(router).await?;
            if volumes.iter().any(|volume| {
                volume.id.as_deref() == Some(media) && volume.filesystem.as_deref() == Some("ext4")
            }) {
                return Ok(());
            }
            sleep(INITIALIZE_POLL).await;
        }
    })
    .await;
    polled.unwrap_or_else(|_elapsed| {
        Err(DomainError::Workflow(WorkflowError::VerificationFailed {
            field: format!("show media {media} filesystem"),
        }))
    })
}

/// Converts a storage plan into a protected workflow request.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = request
        .value()
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let line = match request.path.as_str() {
        "system eject" => format!("system eject {name}"),
        "media initialize" => format!(
            "media {name} initialize {}",
            request
                .value()
                .get("preset")
                .and_then(Value::as_str)
                .ok_or(DomainError::InvalidResponse)?
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(CliChangeRequest::new(
        vec![ValidatedCli::new(line, request.clone())?],
        Vec::new(),
        Permission::Destructive,
        json!({"operation":request.path}),
    ))
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

/// Admits a destructive change of `media`: the role's `Destructive` permission on the
/// router, the confirmation, the medium as one CLI word, and the acknowledgement when it is
/// the drive Entware runs from.
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`], [`DomainError::ConfirmationRequired`],
/// [`DomainError::InvalidCliToken`] or [`DomainError::EntwareDriveInUse`], in that order.
fn admit(
    (router_name, role, confirmed): (&str, &Role, bool),
    media: &str,
    (entware_media, entware_acknowledged): (Option<&str>, bool),
) -> Result<()> {
    authorize(role, Permission::Destructive, router_name)
        .map_err(|_error| DomainError::PermissionDenied)?;
    confirm(confirmed)?;
    validate_token(media)?;
    if entware_media == Some(media) && !entware_acknowledged {
        return Err(DomainError::EntwareDriveInUse);
    }
    Ok(())
}

/// Requires explicit confirmation before catalog or router work.
///
/// # Errors
///
/// Returns an error when the destructive change is not confirmed
/// ([`DomainError::ConfirmationRequired`]).
const fn confirm(confirmed: bool) -> Result<()> {
    if confirmed {
        Ok(())
    } else {
        Err(DomainError::ConfirmationRequired)
    }
}
