//! Curated router domains shared by the Web, MCP, and CLI front-ends.
#![expect(
    clippy::missing_errors_doc,
    reason = "the public Result alias and one shared decode helper keep domain signatures uniform"
)]
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API is exercised by integration tests and downstream crates"
    )
)]

extern crate alloc;

pub mod clients;
pub mod configuration;
pub mod dhcp;
pub mod diagnostics;
pub mod internet;
pub mod segments;
pub mod system;

use alloc::sync::Arc;
use core::result::Result as CoreResult;

use kcc_app::{permissions::Permission, workflow::VerificationSpec};
use kcc_catalog::{Catalog, Risk, ValidatedRequest, ValidationIssue};
use kcc_rci::{RciBody, RciClient, RciError, RciPath};
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Router execution context for typed domain reads and planning.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RouterCtx {
    /// Shared authenticated request client.
    pub client: Arc<RciClient>,
    /// Firmware- and model-specific command view.
    pub catalog: Catalog,
}

impl RouterCtx {
    /// Creates a domain context.
    #[inline]
    #[must_use]
    pub const fn new(client: Arc<RciClient>, catalog: Catalog) -> Self {
        Self { client, catalog }
    }
}

/// Stable domain identifier used by every presentation surface.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum DomainId {
    /// Router identity, clock, and global settings.
    System,
    /// Internet state and ping-check profiles.
    Internet,
    /// Persistence and recovery safety controls.
    Configuration,
    /// Logs and network diagnostic jobs.
    Diagnostics,
    /// Connected clients and hotspot controls.
    Clients,
    /// DHCP pools, leases, bindings, and neighbours.
    Dhcp,
    /// UI-visible network segments.
    Segments,
}

/// One operation exposed by a domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OperationDescriptor {
    /// Stable operation name.
    pub name: &'static str,
    /// Catalog command needed by the operation.
    pub catalog_path: &'static str,
    /// Operational risk.
    pub risk: Risk,
    /// Permission needed to execute the operation.
    pub permission: Permission,
    /// Whether the router persists the command immediately.
    pub persists_immediately: bool,
}

impl OperationDescriptor {
    /// Returns whether this operation exists in `catalog`.
    #[inline]
    #[must_use]
    pub fn available(self, catalog: &Catalog) -> bool {
        catalog.lookup(self.catalog_path).is_some()
    }
}

/// Metadata for one curated domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DomainDescriptor {
    /// Stable domain id.
    pub id: DomainId,
    /// Read operation inventory.
    pub read_ops: &'static [OperationDescriptor],
    /// Write operation inventory.
    pub write_ops: &'static [OperationDescriptor],
    /// Router components needed by the domain.
    pub required_components: &'static [&'static str],
}

impl DomainDescriptor {
    /// Filters reads to commands available on a router.
    #[inline]
    pub fn available_reads(
        &self,
        catalog: &Catalog,
    ) -> impl Iterator<Item = &'static OperationDescriptor> {
        self.read_ops
            .iter()
            .filter(|operation| operation.available(catalog))
    }

    /// Filters writes to commands available on a router.
    #[inline]
    pub fn available_writes(
        &self,
        catalog: &Catalog,
    ) -> impl Iterator<Item = &'static OperationDescriptor> {
        self.write_ops
            .iter()
            .filter(|operation| operation.available(catalog))
    }
}

/// A catalog-validated write plan. Execution belongs exclusively to `ChangeSet`.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ChangeOp {
    /// Requests validated against the target router's catalog.
    pub requests: Vec<ValidatedRequest>,
    /// Read-back expectations.
    pub verify: Vec<VerificationSpec>,
    /// Maximum operation risk.
    pub risk: Risk,
    /// Permission required at execution time.
    pub permission: Permission,
    /// Whether this operation persists immediately rather than remaining unsaved.
    pub persists_immediately: bool,
}

impl ChangeOp {
    /// Creates a write plan.
    #[inline]
    #[must_use]
    pub const fn new(
        requests: Vec<ValidatedRequest>,
        verify: Vec<VerificationSpec>,
        risk: Risk,
        permission: Permission,
        persists_immediately: bool,
    ) -> Self {
        Self {
            requests,
            verify,
            risk,
            permission,
            persists_immediately,
        }
    }
}

/// Domain-layer failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// RCI input or request failed.
    #[error(transparent)]
    Rci(#[from] RciError),
    /// A typed response could not be decoded.
    #[error("router returned an invalid domain response")]
    InvalidResponse,
    /// Catalog validation rejected a planned operation.
    #[error("domain operation is unavailable or invalid")]
    Validation {
        /// Detailed catalog failures.
        issues: Vec<ValidationIssue>,
    },
    /// A confirmation string did not match the router name.
    #[error("factory reset confirmation does not match router name")]
    ConfirmationMismatch,
    /// A static lease is outside the subnet of its bound pool.
    #[error("static lease address is outside the bound DHCP pool subnet")]
    StaticLeaseOutsidePool,
    /// A static lease address is already assigned to another MAC.
    #[error("static lease address is already assigned to another MAC")]
    StaticLeaseAddressInUse,
}

/// Domain result alias.
pub type Result<T> = CoreResult<T, DomainError>;

/// Reads and decodes one typed show resource.
pub(crate) async fn read_show<T>(client: &RciClient, segments: &[&str]) -> Result<T>
where
    T: DeserializeOwned,
{
    let path = RciPath::from_segments(segments).map_err(|_error| DomainError::InvalidResponse)?;
    let RciBody::Json(response) = client.show(&path, &()).await? else {
        return Err(DomainError::InvalidResponse);
    };
    serde_json::from_value(response.value).map_err(|_error| DomainError::InvalidResponse)
}

/// Returns the complete domain registry.
#[inline]
#[must_use]
pub const fn registry() -> &'static [DomainDescriptor] {
    &[
        system::DESCRIPTOR,
        internet::DESCRIPTOR,
        configuration::DESCRIPTOR,
        diagnostics::DESCRIPTOR,
        clients::DESCRIPTOR,
        dhcp::DESCRIPTOR,
        segments::DESCRIPTOR,
    ]
}
