//! Internet status and ping-check operations.

use alloc::collections::BTreeMap;

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DomainDescriptor, DomainId, OperationDescriptor, Result, RouterCtx, read_show};

/// Tolerant internet-status model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub struct InternetStatus {
    /// Connection state, when reported.
    pub status: Option<String>,
    /// Active interface, when reported.
    pub interface: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant ping-check profile collection.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PingCheckProfiles {
    /// Profile array or object supplied by firmware.
    pub profile: Option<Value>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Internet read inventory.
const READS: &[OperationDescriptor] = &[
    OperationDescriptor {
        name: "internet_status",
        catalog_path: "show internet status",
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    },
    OperationDescriptor {
        name: "ping_check",
        catalog_path: "show ping-check",
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    },
];

/// Internet domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Internet,
    read_ops: READS,
    write_ops: &[],
    required_components: &[],
};

/// Reads `show internet status`.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_status(router: &RouterCtx) -> Result<InternetStatus> {
    read_show(&router.client, &["show", "internet", "status"]).await
}

/// Reads all ping-check profiles.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_ping_check(router: &RouterCtx) -> Result<PingCheckProfiles> {
    read_show(&router.client, &["show", "ping-check"]).await
}
