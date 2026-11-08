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

mod cli_token;
mod descriptor;

pub mod clients;
pub mod components;
pub mod configuration;
pub mod dhcp;
pub mod diagnostics;
pub mod dns;
pub mod firewall;
pub mod interfaces;
pub mod internet;
pub mod keendns;
pub mod logging;
pub mod mesh;
pub mod nat;
pub mod policies;
pub mod router_users;
pub mod routing;
pub mod schedules;
pub mod segments;
pub mod services;
pub mod storage;
pub mod system;
pub mod verification;
pub mod vpn_clients;
pub mod vpn_servers;
pub mod wan;
pub mod wifi;

use alloc::sync::Arc;
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{VerificationSpec, WorkflowError},
};
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
    /// Router login accounts and service tags.
    RouterUsers,
    /// Static routes and routing-table views.
    Routing,
    /// Connection policies and their routing rules.
    Policies,
    /// NAT interfaces, forwarding rules, and runtime translations.
    Nat,
    /// Access lists, interface bindings, and UPnP redirects.
    Firewall,
    /// Router services and management listeners.
    Services,
    /// Firmware component management and update policy.
    Components,
    /// Attached storage inventory and maintenance.
    Storage,
    /// Named schedules and timed actions.
    Schedules,
    /// KeenDNS and remote-access controls.
    KeenDns,
    /// Router log reading and configuration.
    Logging,
    /// DNS proxy, resolvers, records, and domain lists.
    Dns,
    /// VPN client tunnels and imports.
    VpnClients,
    /// VPN server configuration and service state.
    VpnServers,
    /// Physical and logical router interfaces.
    Interfaces,
    /// Internet connection interfaces.
    Wan,
    /// Wireless access points, radios, and stations.
    Wifi,
    /// Mesh members and maintenance actions.
    Mesh,
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
    /// States why this operation has no readable postcondition, if it is an action.
    #[inline]
    #[must_use]
    pub fn action_without_state(self) -> Option<&'static str> {
        verification::action_without_state(self.catalog_path)
    }

    /// Returns whether this operation exists in `catalog`.
    #[inline]
    #[must_use]
    pub fn available(self, catalog: &Catalog) -> bool {
        catalog.lookup(self.catalog_path).is_some()
    }

    /// Returns whether the router persists this operation at once on `catalog`'s
    /// firmware: the descriptor's own flag or the catalog's `persists_immediately`.
    #[inline]
    #[must_use]
    pub fn persists_immediately_on(self, catalog: &Catalog) -> bool {
        self.persists_immediately
            || catalog
                .lookup(self.catalog_path)
                .is_some_and(|command| command.persists_immediately)
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

    /// Returns whether the router persists this plan at once: its own flag or any
    /// catalog-flagged request (no save needed, not undone by the fail-safe timer).
    #[inline]
    #[must_use]
    pub fn persists(&self) -> bool {
        self.persists_immediately
            || self
                .requests
                .iter()
                .any(|request| request.persists_immediately)
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
    /// A protected router login would lose required access.
    #[error("protected router account operation refused")]
    ProtectedAccount,
    /// A value cannot be represented as one safe router CLI token.
    #[error("value is not a valid router CLI token")]
    InvalidCliToken,
    /// A destructive operation lacks explicit confirmation.
    #[error("destructive operation requires explicit confirmation")]
    ConfirmationRequired,
    /// The caller lacks the operation permission or router scope.
    #[error("permission denied for domain operation")]
    PermissionDenied,
    /// Protected workflow execution failed.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// A single-route operation produced a router-wide clearing status.
    #[error("route operation aborted because the router reported a broad clear")]
    SafetyAbort,
    /// Route removal did not decrease the fresh route count by exactly one.
    #[error("route removal verification failed")]
    RouteCountMismatch,
    /// The requested access-list rule was absent before a removal attempt.
    #[error("firewall rule is absent")]
    FirewallRuleAbsent,
    /// A fresh running configuration did not contain the expected full rule identity.
    #[error("firewall rule verification failed")]
    FirewallVerificationFailed,
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
        router_users::DESCRIPTOR,
        routing::descriptor::DESCRIPTOR,
        policies::descriptor::DESCRIPTOR,
        nat::descriptor::DESCRIPTOR,
        firewall::descriptor::DESCRIPTOR,
        services::DESCRIPTOR,
        components::DESCRIPTOR,
        storage::DESCRIPTOR,
        schedules::DESCRIPTOR,
        keendns::DESCRIPTOR,
        logging::DESCRIPTOR,
        dns::DESCRIPTOR,
        vpn_clients::DESCRIPTOR,
        vpn_servers::DESCRIPTOR,
        interfaces::DESCRIPTOR,
        wan::DESCRIPTOR,
        wifi::DESCRIPTOR,
        mesh::DESCRIPTOR,
    ]
}
