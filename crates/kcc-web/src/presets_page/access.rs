//! One request on one preset run: the wizard's visit over the run's record.
//!
//! A run also reads its settings with their secrets and the target's inventory.

use alloc::sync::Arc;
use core::str::FromStr as _;

use kcc_migrate::{
    inventory::{InventoryClient, TargetInventory},
    presets::model::Preset,
};
use kcc_rci::version::FirmwareVersion;

use super::{record::Record, saved, steps::Origin};
use crate::wizard::{
    analysis::{Problem, inventory_problem},
    flow::Flow as _,
    retention, visit,
};

/// An opened run, holding its turn until it is dropped.
pub(super) type Visit<'call> = visit::Visit<'call, Record>;

/// What a preset run reads besides its record.
pub(super) trait PresetRun {
    /// The run's settings with their secrets, to plan and apply them: the saved preset,
    /// or the copy's sealed transient preset.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Source`] when they cannot be read: the preset was deleted or
    /// is out of scope, or the copied settings expired.
    // cancel-safe: reads only.
    async fn preset(&self) -> Result<Preset, Problem>;

    /// The target's inventory, read once for the run's settings and kept in its session.
    ///
    /// # Errors
    ///
    /// Returns why the target cannot be used: it did not answer, or runs firmware older
    /// than the settings' or below 4.3.
    // cancel-safe: every router operation is a read.
    async fn inventory(&self, preset: &Preset) -> Result<Arc<TargetInventory>, Problem>;
}

impl PresetRun for Visit<'_> {
    // cancel-safe: reads only.
    async fn preset(&self) -> Result<Preset, Problem> {
        let services = self.services();
        let (store, now) = (services.store(), services.state().unix_seconds());
        let found = match self.record().origin() {
            Origin::Preset { id, name: _ } => {
                let role = services.user().role();
                match saved::load_for_apply(services.fleet(), role, id).await {
                    Ok(preset) => Some(preset),
                    Err(error) => {
                        tracing::warn!(%error, "preset of a run could not be read");
                        None
                    }
                }
            }
            Origin::Copy if retention::idle::<Record>(&store, self.record().id(), now).await => {
                None
            }
            Origin::Copy => {
                let name = self.record().source_router().unwrap_or_default().to_owned();
                match saved::transient(services, self.record().id(), name).await {
                    Ok(preset) => preset,
                    Err(error) => {
                        tracing::warn!(%error, "copied settings could not be read");
                        None
                    }
                }
            }
        };
        found.ok_or(Problem::Source)
    }

    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, every router operation is a read.
    async fn inventory(&self, preset: &Preset) -> Result<Arc<TargetInventory>, Problem> {
        let target = self.record().target().ok_or(Problem::Unreachable)?;
        if let Some(kept) = self.session().inventory(target) {
            return Ok(kept);
        }
        let firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
            .map_err(|_error| Problem::Source)?;
        let client = self
            .services()
            .fleet()
            .registry()
            .bootstrap_client(self.services().user().role(), target)
            .await
            .map_err(|error| {
                tracing::warn!(%error, router = target, "preset run target: no client");
                Problem::Unreachable
            })?;
        let inventory =
            TargetInventory::collect(&InventoryClient::from_client(&client), Some(firmware))
                .await
                .map_err(|error| inventory_problem(&error))?;
        let kept = Arc::new(inventory);
        self.session().keep_inventory(target, Arc::clone(&kept));
        Ok(kept)
    }
}
