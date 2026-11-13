//! MCP server exposing catalog-validated router control to AI agents.
//!
//! The crate root holds the public types the `kcc` binary and the Web UI depend on; tool
//! families live in `generic` (fleet, catalog, raw RCI, jobs), `domains` (curated
//! read/write tools), `config_tools` (state, save, backups), and `migration_tools`.
#![expect(
    clippy::absolute_paths,
    clippy::arithmetic_side_effects,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::multiple_inherent_impl,
    clippy::needless_pass_by_value,
    clippy::shadow_reuse,
    clippy::too_many_arguments,
    reason = "RMCP adapters contain schema-only private types and macro-mandated handler shapes; bounded pagination and owned deserialization are explicit protocol boundaries"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private RMCP schema carriers and dispatch helpers are described by their exported JSON schemas and tool metadata"
    )
)]
extern crate alloc;

mod config_tools;
mod domains;
mod generic;
mod handler;
mod migration_tools;
mod preset_tools;
mod prompts;
pub mod registry;
mod support;
#[cfg(test)]
mod tests;

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::Mutex;

use kcc_app::{
    api_key_use::KeyUseRecorder,
    audit::AuditLog,
    jobs::JobRunner,
    permissions::{Permission, Role, ToolSpec},
    poller::Poller,
    registry::{RouterRegistry, authorize},
    role_source::RoleSource,
    settings::{McpConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use rmcp::handler::server::tool::ToolRouter;

use crate::{
    migration_tools::state::Migrations, preset_tools::state::Presets, support::validate::valid_host,
};

/// A validated router profile id used by shared multi-router authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RouterId(String);

impl RouterId {
    /// Validates and constructs a router id.
    ///
    /// # Errors
    ///
    /// Returns `invalid_arguments` when the id is not a lowercase profile slug.
    #[inline]
    pub fn new(value: String) -> Result<Self, McpFailure> {
        valid_host(&value)?;
        Ok(Self(value))
    }

    /// Returns the router profile id.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Request identity resolved to one application role.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct McpIdentity {
    /// Stable authenticated identity name.
    pub name: String,
    /// Application role used for fine-grained authorization.
    pub role: Role,
}

impl McpIdentity {
    /// Creates a resolved identity.
    #[inline]
    #[must_use]
    pub const fn new(name: String, role: Role) -> Self {
        Self { name, role }
    }
}

/// Authorizes one permission for every router in an atomic multi-router operation.
///
/// # Errors
///
/// Returns the first registry authorization denial.
#[inline]
pub fn authorize_routers(
    identity: &McpIdentity,
    permission: Permission,
    routers: &[RouterId],
) -> Result<(), McpFailure> {
    for router in routers {
        authorize(&identity.role, permission, router.as_str()).map_err(|error| {
            tracing::warn!(
                identity = %identity.name,
                router = router.as_str(),
                error = ?error,
                "MCP router authorization denied"
            );
            McpFailure::Forbidden
        })?;
    }
    Ok(())
}

/// Stable errors exposed by the MCP adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum McpFailure {
    /// Tool arguments failed boundary validation.
    InvalidArguments,
    /// Application permission or router scope denied the operation.
    Forbidden,
    /// The operation needs `confirm: true`, which the call did not set.
    ConfirmRequired,
    /// Destructive operations are off: `[mcp] allow_destructive` is `false`.
    DestructiveDisabled,
    /// The router could not be reached.
    RouterUnreachable,
    /// The router rejected an otherwise valid request.
    RouterRejected,
    /// The router reports neither a system mode kcc knows nor a fail-safe timer; nothing was sent.
    RouterModeUnknown,
    /// The management change applied, but its recovery timer could not be disarmed.
    ManagementAppliedFailSafeArmed,
    /// The configuration was saved, but its recovery timer could not be disarmed.
    ManagementSavedFailSafeArmed,
    /// Work failed or its outcome is unknown, and recovery remains armed.
    ManagementOutcomeUnknownFailSafeArmed,
    /// The arm was refused and so was its disarm: nothing else was sent, and recovery may
    /// remain armed.
    ManagementNotSentFailSafeArmed,
    /// The recovery arm was refused and its disarm accepted: nothing was applied and the
    /// timer is off. The wire code is the cause's.
    NotApplied {
        /// Why the arm was refused.
        cause: Box<Self>,
    },
    /// The live configuration was committed, but startup configuration was not saved.
    ManagementAppliedNotSaved,
    /// Commit was refused locally; nothing was sent and recovery remains armed.
    ManagementNotCommittedFailSafeArmed,
    /// A completed batch retains its item results when recovery cleanup fails.
    BatchFailSafeArmed {
        /// Whether at least one change item succeeded.
        applied: bool,
        /// Redacted batch result with the existing per-item wire fields.
        completion: Box<serde_json::Value>,
    },
    /// Catalog or argument validation failed; nothing was sent.
    ValidationFailed,
    /// The router accepted a change but reading it back still shows the old value.
    VerificationFailed {
        /// JSON pointer of the field that read back unchanged.
        field: String,
    },
    /// Concurrent state made the operation unsafe.
    Conflict,
    /// A background job could not be admitted; retrying is safe.
    JobUnavailable,
    /// An internal service failed.
    Internal,
    /// The target firmware is documentation-based and the caller did not acknowledge it.
    UnverifiedFirmwareTier,
    /// The router accepted the rollback and is restarting with its saved configuration;
    /// the migration is closed, so no retry reboots it again.
    MigrationRollbackRestarting,
}

impl McpFailure {
    /// Stable wire code.
    fn code(&self) -> &'static str {
        match self {
            Self::NotApplied { cause } => cause.code(),
            Self::InvalidArguments => "invalid_arguments",
            Self::Forbidden => "forbidden",
            Self::ConfirmRequired => "confirm_required",
            Self::DestructiveDisabled => "destructive_disabled",
            Self::RouterUnreachable => "router_unreachable",
            Self::RouterRejected => "router_rejected",
            Self::RouterModeUnknown => "router_mode_unknown",
            Self::ManagementAppliedFailSafeArmed
            | Self::BatchFailSafeArmed {
                applied: true,
                completion: _,
            } => "management_applied_fail_safe_armed",
            Self::ManagementOutcomeUnknownFailSafeArmed
            | Self::BatchFailSafeArmed {
                applied: false,
                completion: _,
            } => "management_outcome_unknown_fail_safe_armed",
            Self::ManagementSavedFailSafeArmed => "management_saved_fail_safe_armed",
            Self::ManagementNotSentFailSafeArmed => "management_not_sent_fail_safe_armed",
            Self::ManagementAppliedNotSaved => "management_applied_not_saved",
            Self::ManagementNotCommittedFailSafeArmed => "management_not_committed_fail_safe_armed",
            Self::ValidationFailed => "validation_failed",
            Self::VerificationFailed { field: _ } => "verification_failed",
            Self::Conflict => "conflict",
            Self::JobUnavailable => "job_unavailable",
            Self::Internal => "internal",
            Self::UnverifiedFirmwareTier => "unverified_firmware_tier",
            Self::MigrationRollbackRestarting => "migration_rollback_restarting",
        }
    }
}

/// Application services and filtered RMCP tool dispatch.
#[derive(Clone)]
#[non_exhaustive]
pub struct KccMcp {
    config: McpConfig,
    privacy: PrivacyConfig,
    registry: Arc<RouterRegistry>,
    workflow: Arc<ChangeWorkflow>,
    jobs: Arc<JobRunner>,
    poller: Arc<Poller>,
    roles: RoleSource,
    fallback_role: Role,
    key_use: Option<Arc<KeyUseRecorder>>,
    tool_router: ToolRouter<Self>,
    tool_specs: Arc<[ToolSpec]>,
    pseudonyms: Arc<Mutex<BTreeMap<String, String>>>,
    audit: Option<AuditLog>,
    migrations: Arc<Migrations>,
    presets: Arc<Presets>,
}

impl fmt::Debug for KccMcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KccMcp")
            .field("config", &self.config)
            .field("privacy", &self.privacy)
            .field("registry", &self.registry)
            .field("workflow", &self.workflow)
            .field("jobs", &self.jobs)
            .field("poller", &self.poller)
            .field("roles", &self.roles)
            .field("fallback_role", &self.fallback_role)
            .field("tool_specs", &self.tool_specs)
            .finish_non_exhaustive()
    }
}
