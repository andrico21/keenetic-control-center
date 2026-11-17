//! Planning a preset onto a target: authorization, the read-only target inventory, the plan.

extern crate alloc;

use alloc::collections::BTreeSet;
use core::{fmt::Write as _, str::FromStr as _};

use kcc_app::permissions::{Permission, Role};
use kcc_i18n::keys;
use kcc_migrate::{
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, MigrationMaps},
    presets::{
        model::Preset,
        plan::{PresetMode, PresetPlan, PresetPlanError, plan},
    },
};
use kcc_rci::version::FirmwareVersion;
use serde_json::{Value, json};

use super::args::{ApplyOptions, Mode};
use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
};

/// A preset planned against the target's current inventory.
pub(super) struct Planned {
    /// Target router id.
    target: String,
    /// The principal's role narrowed to the source and target routers.
    role: Role,
    /// The reviewed plan after `--exclude`.
    plan: PresetPlan,
    /// The inventory the plan was made against.
    inventory: TargetInventory,
}

impl Planned {
    /// Authorizes the source and `target` before any router request, reads the target's
    /// inventory (read-only) and plans `preset` with `options`.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal (also for older target firmware or an unacknowledged
    /// documentation tier), inventory or validation failures.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads the target only.
    pub(super) async fn make(
        ctx: &Ctx,
        services: &Services,
        preset: &Preset,
        (target, options): (&str, &ApplyOptions),
    ) -> Outcome<Self> {
        let mut routers = vec![target];
        routers.extend(preset.source_router().filter(|source| *source != target));
        let role = ctx
            .principal()
            .authorize(&[Permission::Read, Permission::Migrate], &routers)?;
        let source_firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
            .map_err(|error| Failure::text(Exit::Validation, &error))?;
        let client = services.registry().bootstrap_client(&role, target).await?;
        let inventory = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_firmware),
        )
        .await
        .map_err(|error| inventory_failure(error, target))?;
        let mut choices = Choices::default();
        choices.ack_documentation_tier = options.ack_documentation_tier;
        let mode = match options.mode {
            Mode::Merge => PresetMode::Merge,
            Mode::Mirror => PresetMode::Mirror,
        };
        let mut reviewed = plan(
            preset,
            &inventory,
            mode,
            &MigrationMaps::default(),
            &choices,
        )
        .map_err(|error| plan_failure(&error, preset, (target, &inventory)))?;
        let excluded = options.exclude.iter().copied().collect::<BTreeSet<_>>();
        reviewed
            .items
            .retain(|item| !excluded.contains(&item.index));
        Ok(Self {
            target: target.to_owned(),
            role,
            plan: reviewed,
            inventory,
        })
    }

    /// Splits into the narrowed role, the plan and the inventory.
    pub(super) fn into_parts(self) -> (Role, PresetPlan, TargetInventory) {
        (self.role, self.plan, self.inventory)
    }

    /// Refuses a plan that still needs input.
    ///
    /// # Errors
    ///
    /// Returns a validation failure naming the needed inputs.
    pub(super) fn ready(&self) -> Outcome {
        if self.plan.is_ready() {
            return Ok(());
        }
        let needed = self
            .plan
            .items
            .iter()
            .filter_map(|item| item.needed_input.as_ref())
            .map(|input| serde_json::to_string(input).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("; ");
        Err(Failure::message(
            Exit::Validation,
            keys::CLI_PRESET_BLOCKED,
            &[("value", &needed)],
        ))
    }

    /// The plan as a JSON document and as text: item numbers, dispositions, reasons and
    /// the redacted source lines.
    ///
    /// # Errors
    ///
    /// Returns serialization failures.
    pub(super) fn render(&self, ctx: &Ctx, preset: &Preset) -> Outcome<(Value, String)> {
        let shown = preset.redacted();
        let mut human = ctx.out().tr(
            keys::CLI_PRESET_PLAN,
            &[
                ("name", &preset.id),
                ("router", &self.target),
                (
                    "value",
                    &format!("{:?}", self.plan.mode).to_ascii_lowercase(),
                ),
                ("count", &self.plan.items.len().to_string()),
            ],
        );
        for item in &self.plan.items {
            let disposition = serde_json::to_value(item.disposition)?;
            let line = shown
                .lines
                .get(item.index)
                .map_or_else(|| "-".to_owned(), ToString::to_string);
            let _ignored = write!(
                human,
                "\n  #{:<3} {:<12} {:<28} {line}",
                item.index,
                disposition.as_str().unwrap_or_default(),
                item.reason
            );
        }
        let value = json!({
            "preset": preset.id,
            "router": self.target,
            "status": if self.plan.is_ready() { "ready" } else { "blocked" },
            "plan": serde_json::to_value(&self.plan)?,
        });
        Ok((value, human))
    }
}

/// Maps an inventory failure; an older target firmware is a policy refusal.
fn inventory_failure(error: InventoryError, target: &str) -> Failure {
    match error {
        InventoryError::TargetFirmwareOlder {
            source_version,
            target_version,
        } => older(
            target,
            &source_version.to_string(),
            &target_version.to_string(),
        ),
        InventoryError::Rci(rci) => rci.into(),
        InventoryError::SourceVersionRequired
        | InventoryError::UnsupportedFirmware
        | InventoryError::ConfigEncoding
        | InventoryError::Parse(_)
        | InventoryError::Catalog
        | _ => Failure::text(Exit::Router, &error),
    }
}

/// Maps a planning refusal.
fn plan_failure(
    error: &PresetPlanError,
    preset: &Preset,
    (target, inventory): (&str, &TargetInventory),
) -> Failure {
    match error {
        PresetPlanError::TargetFirmwareOlder => older(
            target,
            &preset.source.firmware_version,
            &inventory
                .info
                .firmware
                .map_or_default(|version| version.to_string()),
        ),
        PresetPlanError::DocumentationTierAcknowledgementRequired => {
            Failure::message(Exit::Policy, keys::MIGRATE_APPLY_TIER, &[])
        }
        PresetPlanError::UnsupportedFirmware | PresetPlanError::InvalidSourceFirmware | _ => {
            Failure::text(Exit::Validation, error)
        }
    }
}

/// The `TargetFirmwareOlder` refusal (exit 10).
fn older(target: &str, source: &str, found: &str) -> Failure {
    Failure::message(
        Exit::Policy,
        keys::CLI_PRESET_TARGET_OLDER,
        &[("router", target), ("version", source), ("value", found)],
    )
}
