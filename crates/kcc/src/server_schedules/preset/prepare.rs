//! Planning a scheduled preset against a fresh inventory of its router, as the run and the
//! creation-time check both do.

extern crate alloc;

use alloc::sync::Arc;
use core::{iter, str::FromStr as _};

use kcc_app::{
    audit::Actor,
    permissions::{Permission, Role},
    registry::authorize,
};
use kcc_migrate::{
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, MigrationMaps},
    presets::{
        apply::{PresetApplyError, PresetApplyRequest, request as protect},
        model::Preset,
        plan::{PresetMode, PresetPlanError, plan},
        store::PresetError,
        unattended::refusal,
    },
};
use kcc_rci::version::FirmwareVersion;
use tokio::task::spawn_blocking;

use super::{Prepared, PresetRefusal, Target};
use crate::server_schedules::actions::ActionDeps;

/// What planning needs on the router and on the preset's source router.
const PLANNING: [Permission; 2] = [Permission::Read, Permission::Migrate];

/// Plans `target`'s preset for `role` and builds the protected request of `actor`.
///
/// The preset is opened with `role` and planned in Merge mode against a fresh inventory of
/// the router, with the role narrowed to the router and the preset's source router; the
/// request runs on the action's apply clock.
///
/// # Errors
///
/// Why the preset cannot run unattended now.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
pub(super) async fn request(
    deps: &ActionDeps,
    target: Target<'_>,
    (role, actor): (&Role, Actor),
) -> Result<Prepared, PresetRefusal> {
    let preset = load(deps, role, target.preset_id).await?;
    let source = preset.source_router().map(str::to_owned);
    let narrowed = narrowed(role, target.router, source.as_deref())?;
    let firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
        .map_err(|_invalid| PresetRefusal::Firmware)?;
    let client = deps
        .registry()
        .bootstrap_client(&narrowed, target.router)
        .await
        .map_err(|_error| PresetRefusal::Router)?;
    let inventory =
        TargetInventory::collect(&InventoryClient::from_client(&client), Some(firmware))
            .await
            .map_err(|error| inventory_refusal(&error))?;
    let mut choices = Choices::default();
    choices.ack_documentation_tier = target.ack_documentation_tier;
    let reviewed = plan(
        &preset,
        &inventory,
        PresetMode::Merge,
        &MigrationMaps::default(),
        &choices,
    )
    .map_err(|error| plan_refusal(&error))?;
    let input = PresetApplyRequest::new(
        Arc::clone(deps.workflow()),
        deps.audit().clone(),
        actor,
        narrowed,
        target.router.to_owned(),
        preset,
        reviewed.clone(),
        inventory,
    );
    let mut request = protect(input).map_err(request_refusal)?;
    if let Some(refused) = refusal(&reviewed, &request) {
        return Err(refused.into());
    }
    request.options.clock = Arc::clone(deps.apply_clock());
    Ok(Prepared { request, source })
}

/// Opens preset `id` for an apply with `role`.
///
/// # Errors
///
/// [`PresetRefusal::Forbidden`] without `Migrate`, else [`PresetRefusal::Unavailable`] for a
/// preset that is missing, outside the role's scope or unreadable.
// cancel-safe: dropped, the blocking read finishes on its own and its result is discarded.
async fn load(deps: &ActionDeps, role: &Role, id: &str) -> Result<Preset, PresetRefusal> {
    let (store, owner, wanted) = (Arc::clone(deps.presets()), role.clone(), id.to_owned());
    match spawn_blocking(move || store.load_for_apply(&owner, &wanted)).await {
        Ok(Ok(preset)) => Ok(preset),
        Ok(Err(PresetError::Forbidden)) => Err(PresetRefusal::Forbidden),
        Ok(Err(_)) | Err(_) => Err(PresetRefusal::Unavailable),
    }
}

/// `role` limited to `target` and the preset's `source` router, after checking that it
/// holds `Read` and `Migrate` on both.
///
/// # Errors
///
/// [`PresetRefusal::Forbidden`].
fn narrowed(role: &Role, target: &str, source: Option<&str>) -> Result<Role, PresetRefusal> {
    let routers = iter::once(target)
        .chain(source.filter(|router| *router != target))
        .collect::<Vec<_>>();
    routers
        .iter()
        .try_for_each(|router| {
            PLANNING
                .iter()
                .try_for_each(|permission| authorize(role, *permission, router))
        })
        .map_err(|_denied| PresetRefusal::Forbidden)?;
    Ok(Role::new(
        role.name.clone(),
        role.permissions.iter().copied(),
        routers.into_iter().map(str::to_owned).collect(),
    ))
}

/// The refusal of an inventory that could not be read.
const fn inventory_refusal(error: &InventoryError) -> PresetRefusal {
    if matches!(
        error,
        InventoryError::TargetFirmwareOlder {
            source_version: _,
            target_version: _,
        } | InventoryError::UnsupportedFirmware
    ) {
        PresetRefusal::Firmware
    } else {
        PresetRefusal::Router
    }
}

/// The refusal of a plan that could not be made.
const fn plan_refusal(error: &PresetPlanError) -> PresetRefusal {
    if matches!(
        error,
        PresetPlanError::DocumentationTierAcknowledgementRequired
    ) {
        PresetRefusal::DocumentationTier
    } else {
        PresetRefusal::Firmware
    }
}

/// The refusal of a plan the protected request was not built from.
const fn request_refusal(error: PresetApplyError) -> PresetRefusal {
    if matches!(error, PresetApplyError::Forbidden) {
        PresetRefusal::Forbidden
    } else {
        PresetRefusal::NotReady
    }
}
