//! One request on one migration: the wizard's visit over the migration's record.
//!
//! A migration also reads its sealed source, the analysis of source and target, and the
//! source router's own inventory.

use alloc::sync::Arc;

use kcc_migrate::inventory::{InventoryClient, TargetInventory};
use secrecy::SecretString;

use super::{analysis::Analysis, kinds::Source, record::Record};
use crate::wizard::{
    analysis::Problem,
    flow::Flow as _,
    store::{Sealed, StoreError},
    visit,
};

/// An opened migration, holding its turn until it is dropped.
pub(super) type Visit<'call> = visit::Visit<'call, Record>;

/// What a migration reads besides its record.
pub(super) trait Migration {
    /// Seals `text` as the source configuration.
    ///
    /// # Errors
    ///
    /// Returns sealing and write failures.
    fn seal_source(&self, text: &SecretString) -> Result<(), StoreError>;

    /// The analysis of the record's source and target: the kept one, or read again.
    ///
    /// # Errors
    ///
    /// Returns why the source or the target cannot be used.
    // cancel-safe: reads only.
    async fn analysis(&self) -> Result<Arc<Analysis>, Problem>;

    /// The source router's own inventory, when the source is a router that answers: the
    /// kept one, or read again.
    // cancel-safe: reads only.
    async fn hardware(&self, analysis: &Analysis) -> Option<Arc<TargetInventory>>;
}

impl Migration for Visit<'_> {
    fn seal_source(&self, text: &SecretString) -> Result<(), StoreError> {
        self.services().store().seal(
            self.services().key(),
            self.record().id(),
            Sealed::Source,
            text,
        )
    }

    // cancel-safe: reads only.
    async fn analysis(&self) -> Result<Arc<Analysis>, Problem> {
        let target = self.record().target().ok_or(Problem::Unreachable)?;
        if let Some(kept) = self.session().analysis(target) {
            return Ok(kept);
        }
        let text = self
            .services()
            .store()
            .open(self.services().key(), self.record().id(), Sealed::Source)
            .map_err(|error| {
                tracing::error!(%error, "migration source could not be opened");
                Problem::Source
            })?
            .ok_or(Problem::Source)?;
        let fresh = Arc::new(
            Analysis::collect(
                self.services().fleet(),
                self.services().user().role(),
                self.record(),
                &text,
            )
            .await?,
        );
        self.session().keep(target, Arc::clone(&fresh));
        Ok(fresh)
    }

    // cancel-safe: reads only.
    async fn hardware(&self, analysis: &Analysis) -> Option<Arc<TargetInventory>> {
        let Some(Source::Router { router }) = self.record().source() else {
            return None;
        };
        if let Some(kept) = self.session().inventory(router) {
            return Some(kept);
        }
        let client = self
            .services()
            .fleet()
            .registry()
            .client(router)
            .await
            .ok()?;
        let firmware = analysis.source().firmware;
        match TargetInventory::collect(&InventoryClient::from_client(&client), firmware).await {
            Ok(inventory) => {
                let kept = Arc::new(inventory);
                self.session().keep_inventory(router, Arc::clone(&kept));
                Some(kept)
            }
            Err(error) => {
                tracing::warn!(%error, router, "migration source inventory failed");
                None
            }
        }
    }
}
