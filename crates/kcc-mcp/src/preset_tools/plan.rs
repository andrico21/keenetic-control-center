//! Arguments of `kcc_preset_apply` and the read-only planning step it shares with dry runs.

use alloc::collections::{BTreeMap, BTreeSet};
use core::str::FromStr as _;

use kcc_app::permissions::Permission;
use kcc_migrate::{
    inventory::TargetInventory,
    maps::MapEntry,
    planner::{Choices, MigrationMaps},
    presets::{
        apply::PresetApplyOptions,
        model::Preset,
        plan::{PresetMode, PresetPlan, PresetPlanError, plan},
    },
};
use kcc_rci::version::FirmwareVersion;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::state::map_preset;
use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers, migration_tools::plan::collect,
    support::validate::valid_text,
};

/// Most item indices in `include` or `exclude`.
const MAX_ITEMS: usize = 4096;

/// How target settings in the preset's groups are reconciled.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    /// Add or update the preset's lines; keep target-only lines.
    #[default]
    Merge,
    /// Merge, then remove target-only lines of the preset's groups.
    Mirror,
}

/// One source object and its target, or `null` to leave it unmapped.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MapPair {
    /// Source object name.
    source: String,
    /// Target object name.
    #[serde(default)]
    target: Option<String>,
}

/// Object mappings from the preset's source onto the target.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MapsInput {
    /// Physical ports.
    #[serde(default)]
    ports: Vec<MapPair>,
    /// Wi-Fi radios.
    #[serde(default)]
    radios: Vec<MapPair>,
    /// Logical interfaces.
    #[serde(default)]
    interfaces: Vec<MapPair>,
    /// Named IP policies.
    #[serde(default)]
    policies: BTreeMap<String, String>,
}

/// Arguments of `kcc_preset_apply`.
#[derive(Debug, Deserialize, JsonSchema)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of the tool's JSON arguments"
)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyInput {
    /// Target router profile id.
    host: String,
    /// Stored or transient preset id.
    preset_id: String,
    /// `merge` (default) or `mirror`.
    #[serde(default)]
    mode: Mode,
    /// Object mappings onto the target.
    #[serde(default)]
    maps: MapsInput,
    /// Plan item indices to keep (empty keeps every item).
    #[serde(default)]
    include: Vec<usize>,
    /// Plan item indices to leave out.
    #[serde(default)]
    exclude: Vec<usize>,
    /// Generate WireGuard private keys on the target (default) instead of copying them.
    #[serde(default = "enabled")]
    regenerate_wireguard_keys: bool,
    /// Acknowledges a target whose firmware support is documentation-based (audited).
    #[serde(default)]
    ack_documentation_tier: bool,
    /// Plan only: read the target inventory and return the plan; nothing is written.
    #[serde(default)]
    dry_run: bool,
    /// Required unless `dry_run`: confirms applying the plan.
    #[serde(default)]
    confirm: bool,
}

/// Serde default `true`.
const fn enabled() -> bool {
    true
}

/// A preset planned against the target's current inventory.
pub(super) struct Planned {
    /// Source router of the preset, when it has one.
    source: Option<RouterId>,
    /// Target router.
    target: RouterId,
    /// The preset, with its protected values.
    preset: Preset,
    /// The reviewed plan after `include`/`exclude`.
    plan: PresetPlan,
    /// The target inventory the plan was made against.
    inventory: TargetInventory,
}

/// Converts mapping pairs.
fn entries(pairs: &[MapPair]) -> Vec<MapEntry> {
    pairs
        .iter()
        .map(|pair| MapEntry::new(pair.source.clone(), pair.target.clone()))
        .collect()
}

/// Maps a planning refusal.
const fn map_plan(error: &PresetPlanError) -> McpFailure {
    match error {
        PresetPlanError::DocumentationTierAcknowledgementRequired => {
            McpFailure::UnverifiedFirmwareTier
        }
        PresetPlanError::TargetFirmwareOlder
        | PresetPlanError::UnsupportedFirmware
        | PresetPlanError::InvalidSourceFirmware
        | _ => McpFailure::ValidationFailed,
    }
}

impl Planned {
    /// The plan as returned to the caller: dispositions, reasons and needed inputs only.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(super) fn view(&self, dry_run: bool) -> Result<Value, McpFailure> {
        let plan = serde_json::to_value(&self.plan).map_err(|_error| McpFailure::Internal)?;
        let status = if self.plan.is_ready() {
            "ready"
        } else {
            "blocked"
        };
        Ok(json!({
            "status": status,
            "dry_run": dry_run,
            "host": self.target.as_str(),
            "preset_id": self.preset.id,
            "plan": plan
        }))
    }

    /// Whether every item is resolved.
    pub(super) fn is_ready(&self) -> bool {
        self.plan.is_ready()
    }

    /// Splits into the source, target, preset, plan and inventory.
    pub(super) fn into_parts(
        self,
    ) -> (
        Option<RouterId>,
        RouterId,
        Preset,
        PresetPlan,
        TargetInventory,
    ) {
        (
            self.source,
            self.target,
            self.preset,
            self.plan,
            self.inventory,
        )
    }
}

impl ApplyInput {
    /// Target router profile id.
    pub(super) fn host(&self) -> &str {
        &self.host
    }

    /// Whether only the plan is wanted.
    pub(super) const fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Preset apply options from the arguments.
    pub(super) fn options(&self) -> PresetApplyOptions {
        if self.regenerate_wireguard_keys {
            PresetApplyOptions::default()
        } else {
            PresetApplyOptions::default().keep_wireguard_keys()
        }
    }

    /// Loads the preset, authorizes source and target, reads the target inventory, and
    /// plans. Authorization happens before any router request; the inventory is read-only.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    // NOT cancel-safe: it only reads the preset and the target inventory, but it may sign in first,
    // and a sign-in dropped mid-way can leave an orphaned router session.
    pub(super) async fn planned(
        &self,
        server: &KccMcp,
        identity: &McpIdentity,
    ) -> Result<Planned, McpFailure> {
        planned(server, identity, self).await
    }
}

/// See [`ApplyInput::planned`].
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only reads the preset and the target inventory; a store read left on the
// blocking pool changes nothing, but it may sign in first, and a sign-in dropped mid-way can leave
// an orphaned router session.
async fn planned(
    server: &KccMcp,
    identity: &McpIdentity,
    input: &ApplyInput,
) -> Result<Planned, McpFailure> {
    if input.include.len() > MAX_ITEMS || input.exclude.len() > MAX_ITEMS {
        return Err(McpFailure::InvalidArguments);
    }
    valid_text(&input.preset_id, 96)?;
    let target = RouterId::new(input.host.clone())?;
    let presets = &server.presets;
    let preset =
        if let Some(transient) = presets.transient(&identity.name, &input.preset_id).await? {
            transient
        } else {
            let (role, id) = (identity.role.clone(), input.preset_id.clone());
            presets
                .stored(move |store| store.load_for_apply(&role, &id))
                .await?
                .map_err(|error| map_preset(&error))?
        };
    let source = preset
        .source_router()
        .map(|router| RouterId::new(router.to_owned()))
        .transpose()?;
    let mut routers = vec![target.clone()];
    routers.extend(source.clone());
    authorize_routers(identity, Permission::Migrate, &routers)?;
    if !input.dry_run && !input.confirm {
        return Err(McpFailure::ConfirmRequired);
    }
    let firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
        .map_err(|_error| McpFailure::ValidationFailed)?;
    let inventory = collect(server, identity, &target, Some(firmware)).await?;
    let mut maps = MigrationMaps::default();
    maps.ports.entries = entries(&input.maps.ports);
    maps.radios.entries = entries(&input.maps.radios);
    maps.interfaces.entries = entries(&input.maps.interfaces);
    maps.policies.clone_from(&input.maps.policies);
    let mut choices = Choices::default();
    choices.ack_documentation_tier = input.ack_documentation_tier;
    let mode = match input.mode {
        Mode::Merge => PresetMode::Merge,
        Mode::Mirror => PresetMode::Mirror,
    };
    let mut reviewed =
        plan(&preset, &inventory, mode, &maps, &choices).map_err(|error| map_plan(&error))?;
    let include = input.include.iter().copied().collect::<BTreeSet<_>>();
    let exclude = input.exclude.iter().copied().collect::<BTreeSet<_>>();
    reviewed.items.retain(|item| {
        (include.is_empty() || include.contains(&item.index)) && !exclude.contains(&item.index)
    });
    Ok(Planned {
        source,
        target,
        preset,
        plan: reviewed,
        inventory,
    })
}
