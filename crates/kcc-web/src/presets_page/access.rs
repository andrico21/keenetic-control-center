//! One request on one preset run: the services, the record, its session, and the checks
//! every handler makes first.
//!
//! A run is opened only by the account that started it (anyone else gets 404), and only
//! while the role still holds `Migrate` on every router it names (403 otherwise), before
//! any request to a router.

use alloc::{collections::BTreeMap, sync::Arc};
use core::str::FromStr as _;

use kcc_migrate::{
    inventory::{InventoryClient, TargetInventory},
    presets::model::Preset,
};
use kcc_rci::version::FirmwareVersion;
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::OwnedMutexGuard;

use super::{
    record::{FILE, Record},
    saved,
    steps::Origin,
};
use crate::{
    migrate_wizard::{
        access::Services,
        analysis::{Problem, inventory_problem},
        ids::is_id,
        service::{Session, Wizards},
        store::{Sealed, StoreError},
    },
    page_kit::context::Refusal,
};

/// An opened run, holding its turn until it is dropped.
pub(super) struct Visit<'call> {
    /// The services.
    services: Services<'call>,
    /// The record as stored when the turn was taken.
    record: Record,
    /// The run's in-memory side.
    session: Arc<Session>,
    /// The run's turn: no other request reads or writes the record meanwhile.
    _turn: OwnedMutexGuard<()>,
}

impl<'call> Visit<'call> {
    /// Opens run `id` for the user of `services`, once it is its turn.
    ///
    /// # Errors
    ///
    /// Returns the refusal: a missing or foreign run is [`Refusal::Missing`], a router
    /// outside the role's `Migrate` scope [`Refusal::Forbidden`].
    // cancel-safe: waits for the turn, then reads.
    pub(super) async fn open(
        services: Services<'call>,
        runs: &Wizards,
        id: &str,
    ) -> Result<Self, Refusal> {
        if !is_id(id) {
            return Err(Refusal::Missing);
        }
        let session = runs.session(id);
        let turn = session.turn().await;
        let record = match services.store().load_named::<Record>(id, FILE) {
            Ok(Some(found))
                if found.current()
                    && found.id() == id
                    && found.owner() == services.user().username() =>
            {
                found
            }
            Ok(_) => return Err(Refusal::Missing),
            Err(error) => return Err(Refusal::Failed(Box::new(error))),
        };
        if !record
            .routers()
            .into_iter()
            .all(|router| services.may_migrate(router))
        {
            return Err(Refusal::Forbidden);
        }
        Ok(Self {
            services,
            record,
            session,
            _turn: turn,
        })
    }

    /// The services.
    pub(super) const fn services(&self) -> Services<'call> {
        self.services
    }

    /// The record.
    pub(super) const fn record(&self) -> &Record {
        &self.record
    }

    /// The record, to change and then [`save`](Self::save).
    pub(super) const fn record_mut(&mut self) -> &mut Record {
        &mut self.record
    }

    /// The run's in-memory side.
    pub(super) fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// Writes the record.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(super) fn save(&self) -> Result<(), StoreError> {
        self.services
            .store()
            .save_named(self.record.id(), FILE, &self.record)
    }

    /// The run's settings with their secrets, to plan and apply them: the saved preset,
    /// or the copy's sealed transient preset.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Source`] when they cannot be read: the preset was deleted or
    /// is out of scope, or the copied settings expired.
    pub(super) fn preset(&self) -> Result<Preset, Problem> {
        let services = self.services;
        let fleet = services.fleet();
        let found = match self.record.origin() {
            Origin::Preset { id, name: _ } => {
                match saved::store(fleet).get_for_apply(services.user().role(), id) {
                    Ok(preset) => Some(preset),
                    Err(error) => {
                        tracing::warn!(%error, "preset of a run could not be read");
                        None
                    }
                }
            }
            Origin::Copy => {
                let name = self.record.source_router().unwrap_or_default().to_owned();
                match saved::transient(services, self.record.id(), name) {
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

    /// The target's inventory, read once for the run's settings and kept in its session.
    ///
    /// # Errors
    ///
    /// Returns why the target cannot be used: it did not answer, or runs firmware older
    /// than the settings' or below 4.3.
    // cancel-safe: every router operation is a read.
    pub(super) async fn inventory(&self, preset: &Preset) -> Result<Arc<TargetInventory>, Problem> {
        let target = self.record.target().ok_or(Problem::Unreachable)?;
        if let Some(kept) = self.session.inventory(target) {
            return Ok(kept);
        }
        let firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
            .map_err(|_error| Problem::Source)?;
        let client = self
            .services
            .fleet()
            .registry()
            .bootstrap_client(self.services.user().role(), target)
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
        self.session.keep_inventory(target, Arc::clone(&kept));
        Ok(kept)
    }

    /// The typed passwords, by user name.
    ///
    /// # Errors
    ///
    /// Returns read, format and opening failures.
    pub(super) fn passwords(&self) -> Result<BTreeMap<String, SecretString>, StoreError> {
        let Some(sealed) =
            self.services
                .store()
                .open(self.services.key(), self.record.id(), Sealed::Passwords)?
        else {
            return Ok(BTreeMap::new());
        };
        let plain: BTreeMap<String, String> =
            serde_json::from_str(sealed.expose_secret()).map_err(|_error| StoreError::Malformed)?;
        Ok(plain
            .into_iter()
            .map(|(user, password)| (user, SecretString::from(password)))
            .collect())
    }

    /// Seals `passwords`, by user name.
    ///
    /// # Errors
    ///
    /// Returns sealing and write failures.
    pub(super) fn seal_passwords(
        &self,
        passwords: &BTreeMap<String, SecretString>,
    ) -> Result<(), StoreError> {
        let plain = passwords
            .iter()
            .map(|(user, password)| (user.as_str(), password.expose_secret()))
            .collect::<BTreeMap<_, _>>();
        let text = SecretString::from(
            serde_json::to_string(&plain).map_err(|_error| StoreError::Malformed)?,
        );
        self.services.store().seal(
            self.services.key(),
            self.record.id(),
            Sealed::Passwords,
            &text,
        )
    }
}
