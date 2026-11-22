//! Entware management over SSH: the shared services and caller of every SSH flow, the
//! enrolment lifecycle (probe, bootstrap, re-pin, revoke, disable) and the package and
//! service operations.
//!
//! The flows build on `kcc-ssh` (pinned transport, closed command set) and on the sealed
//! SSH state of `kcc_app::entware_ssh`. Every flow needs `Permission::Destructive` on the
//! router; a flow that opens an SSH connection first refuses while `opkg chroot` is on and
//! when the router URL host differs from the enrolled one.

pub mod enrol;
pub mod error;
pub mod ops;
mod preflight;
mod report;

use alloc::sync::Arc;
use core::fmt;

use kcc_app::{
    accounts::Clock,
    audit::{Actor, AuditLog},
    entware_ssh::{state::SshStore, ticket::TicketStore},
    permissions::Role,
    registry::RouterRegistry,
    secrets::MasterKey,
    workflow::ChangeWorkflow,
};
use kcc_ssh::{pool::SshPool, transport::Timeouts};
use serde::Serialize;

/// What the SSH flows share: the router registry (outbound policy), the change workflow
/// (router write lease), the audit log, the sealed SSH state and tickets, one session pool
/// and the SSH timeouts.
#[expect(
    clippy::module_name_repetitions,
    reason = "surfaces hold it next to other services as SshServices"
)]
pub struct SshServices {
    /// Router profiles and the outbound policy SSH addresses are admitted by.
    registry: Arc<RouterRegistry>,
    /// The router write lease.
    workflow: Arc<ChangeWorkflow>,
    /// Audit writer.
    audit: AuditLog,
    /// Enrolment records and private keys.
    store: SshStore,
    /// Probe tickets.
    tickets: TicketStore,
    /// Wall clock of tickets, enrolment times and audit entries.
    clock: Arc<dyn Clock>,
    /// One session per router, four in total.
    pool: SshPool,
    /// Connection and command bounds.
    timeouts: Timeouts,
}

impl fmt::Debug for SshServices {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshServices")
            .field("store", &self.store)
            .field("pool", &self.pool)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

impl SshServices {
    /// Services over `workflow`'s state directory, sealing the SSH state with `key`.
    ///
    /// The five collaborators are independent and all required: the workflow owns the
    /// lease, the registry the outbound policy, the audit log the trail, the master key
    /// the sealing and the clock the ticket expiry.
    #[inline]
    #[must_use]
    pub fn new(
        workflow: Arc<ChangeWorkflow>,
        registry: Arc<RouterRegistry>,
        audit: AuditLog,
        key: &MasterKey,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let state = workflow.state().clone();
        Self {
            store: SshStore::new(state.clone(), key.duplicate()),
            tickets: TicketStore::new(state, key.duplicate(), Arc::clone(&clock)),
            registry,
            workflow,
            audit,
            clock,
            pool: SshPool::new(),
            timeouts: Timeouts::default(),
        }
    }

    /// The same services with `timeouts`.
    #[inline]
    #[must_use]
    pub const fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
}

/// Who runs a flow on which router.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Caller<'call> {
    /// The router id.
    pub router: &'call str,
    /// The audited principal.
    pub actor: &'call Actor,
    /// The principal's role.
    pub role: &'call Role,
}

impl<'call> Caller<'call> {
    /// `actor` with `role` on `router`.
    #[inline]
    #[must_use]
    pub const fn new(router: &'call str, actor: &'call Actor, role: &'call Role) -> Self {
        Self {
            router,
            actor,
            role,
        }
    }
}

/// Public facts of one flow, recorded in its audit entry as they become known.
#[derive(Debug, Serialize)]
struct Facts {
    /// The audited flow.
    #[serde(skip)]
    action: report::Action,
    /// The SSH port used.
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    /// Fingerprint of the probed or pinned host key.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    /// Fingerprint of the host key a re-pin replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_fingerprint: Option<String>,
    /// Whether the typed password was Entware's default; the audit log refuses parameter
    /// names that contain "password", so the entry calls it `default_credentials_in_use`.
    #[serde(
        rename = "default_credentials_in_use",
        skip_serializing_if = "Option::is_none"
    )]
    default_password_in_use: Option<bool>,
    /// Whether kcc's key stays in the router's `authorized_keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    entware_key_still_authorized: Option<bool>,
    /// The package an operation names.
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    /// The service an operation names.
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    /// Bytes of SSH output an operation received, standard output and error together.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_bytes: Option<u64>,
    /// SHA-256 of that output, lowercase hex; the output itself is never recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_sha256: Option<String>,
}
