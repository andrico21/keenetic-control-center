//! Conversion from a reviewed preset plan to the protected migration applier.

mod convert;

use alloc::sync::Arc;
use core::fmt;

use kcc_app::{
    audit::{Actor, AuditLog},
    permissions::{Permission, Role},
    registry::authorize,
    workflow::ChangeWorkflow,
};
use kcc_rci::SecretBytes;
use thiserror::Error;

use super::{model::Preset, plan::PresetPlan};
use crate::{
    apply::{ApplyRequest, ApplySource},
    inventory::TargetInventory,
    planner::plain_password,
};

/// Preset-specific apply choices.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PresetApplyOptions {
    /// Generate WireGuard private keys on the target instead of copying captured keys.
    pub regenerate_wireguard_keys: bool,
}

impl Default for PresetApplyOptions {
    #[inline]
    fn default() -> Self {
        Self {
            regenerate_wireguard_keys: true,
        }
    }
}

impl PresetApplyOptions {
    /// Keeps captured WireGuard private keys and emits a warning for each retained key.
    #[inline]
    #[must_use]
    pub const fn keep_wireguard_keys(mut self) -> Self {
        self.regenerate_wireguard_keys = false;
        self
    }
}

/// Services and reviewed values needed to enter the migration applier.
#[non_exhaustive]
pub struct PresetApplyRequest {
    /// Protected workflow service.
    pub workflow: Arc<ChangeWorkflow>,
    /// Audit writer.
    pub audit: AuditLog,
    /// Initiating principal.
    pub actor: Actor,
    /// Principal permissions and router scope.
    pub role: Role,
    /// Registered target router id.
    pub target: String,
    /// Captured preset, retained only in memory for transient copies.
    pub preset: Preset,
    /// Reviewed preset plan.
    pub plan: PresetPlan,
    /// Target facts used to produce the reviewed plan.
    pub inventory: TargetInventory,
    /// Preset-specific choices.
    pub options: PresetApplyOptions,
}

impl fmt::Debug for PresetApplyRequest {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            workflow: _,
            audit: _,
            actor,
            role,
            target,
            preset,
            plan,
            inventory: _,
            options,
        } = self;
        f.debug_struct("PresetApplyRequest")
            .field("actor", actor)
            .field("role", role)
            .field("target", target)
            .field("preset", preset)
            .field("plan", plan)
            .field("options", options)
            .finish_non_exhaustive()
    }
}

impl PresetApplyRequest {
    /// Creates a complete preset apply request from already reviewed target facts.
    #[inline]
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "the request crosses one authorization boundary and every argument is an independent domain object"
    )]
    pub fn new(
        workflow: Arc<ChangeWorkflow>,
        audit: AuditLog,
        actor: Actor,
        role: Role,
        target: String,
        preset: Preset,
        plan: PresetPlan,
        inventory: TargetInventory,
    ) -> Self {
        Self {
            workflow,
            audit,
            actor,
            role,
            target,
            preset,
            plan,
            inventory,
            options: PresetApplyOptions::default(),
        }
    }
}

/// Refusal before the generic applier is allowed to contact a router.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum PresetApplyError {
    /// The caller lacks migration permission or source/target scope.
    #[error("preset apply is forbidden")]
    Forbidden,
    /// The reviewed preset plan still contains unresolved items.
    #[error("preset plan is not ready")]
    PlanNotReady,
    /// A protected executable line could not be converted.
    #[error("preset plan is invalid")]
    InvalidPlan,
}

/// Builds the generic protected request after checking both router scopes.
///
/// No router is contacted by this function. The returned request executes only through
/// [`crate::apply::Applier`]. A line that sets the password of the account kcc signs in
/// with runs in the management phase; when the reviewed plan sends it as plaintext, that
/// password becomes the run's management password, otherwise the caller must supply one.
///
/// # Errors
/// Returns a scope refusal before command conversion, or a plan refusal when unresolved items
/// remain.
#[inline]
pub fn request(input: PresetApplyRequest) -> Result<ApplyRequest, PresetApplyError> {
    authorize(&input.role, Permission::Migrate, &input.target)
        .map_err(|_error| PresetApplyError::Forbidden)?;
    if let Some(source) = input.preset.source_router() {
        authorize(&input.role, Permission::Migrate, source)
            .map_err(|_error| PresetApplyError::Forbidden)?;
    }
    if !input.plan.is_ready() {
        return Err(PresetApplyError::PlanNotReady);
    }
    let acknowledged = input.plan.documentation_tier_acknowledged;
    let (migration, source, warnings) =
        convert::migration_plan(&input.preset, input.plan, &input.inventory, input.options);
    let source_router = input.preset.source_router().map(str::to_owned);
    let mut request = ApplyRequest::new(
        input.workflow,
        input.audit,
        input.actor,
        input.role,
        input.target,
        migration,
        ApplySource::Preset {
            bytes: SecretBytes::from(source.into_bytes()),
            source_router,
        },
    );
    request.options.management_password = request
        .plan
        .phases
        .management
        .iter()
        .find_map(|line| plain_password(line.expose_command(), &input.inventory.login));
    request.options.ack_documentation_tier = acknowledged;
    request.options.initial_warnings = warnings;
    Ok(request)
}
