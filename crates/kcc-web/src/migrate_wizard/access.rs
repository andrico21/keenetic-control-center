//! One request on one migration: the services, the record, its session, and the checks
//! every handler makes first.
//!
//! The route table already requires `Migrate`; a migration is opened only by the account
//! that started it (anyone else gets 404), and only while the role still holds `Migrate`
//! on every router it names (403 otherwise).

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::{permissions::Permission, registry, secrets::MasterKey};
use kcc_migrate::inventory::{InventoryClient, TargetInventory};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::OwnedMutexGuard;

use super::{
    analysis::{Analysis, Problem},
    ids::is_id,
    kinds::Source,
    record::Record,
    service::{Session, Wizards},
    store::{Sealed, Store, StoreError},
};
use crate::{
    WebState,
    authz::CurrentUser,
    fleet::Fleet,
    overview::is_profile_id,
    page_kit::context::{Refusal, lookup},
};

/// The services a migration request uses.
#[derive(Clone, Copy)]
pub(super) struct Services<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router fleet services.
    fleet: &'call Fleet,
}

impl<'call> Services<'call> {
    /// The services of `state` for `user`.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Unavailable`] when the fleet is not attached.
    pub(super) fn of(state: &'call WebState, user: &'call CurrentUser) -> Result<Self, Refusal> {
        let fleet = state.fleet().ok_or(Refusal::Unavailable)?;
        Ok(Self { user, fleet })
    }

    /// The signed-in user.
    pub(super) const fn user(self) -> &'call CurrentUser {
        self.user
    }

    /// Router fleet services.
    pub(super) const fn fleet(self) -> &'call Fleet {
        self.fleet
    }

    /// The migrations directory.
    pub(super) fn store(self) -> Store {
        Store::new(self.fleet.workflow().state().dir())
    }

    /// The key sealing the migrations' secrets: the backups' key.
    pub(super) fn key(self) -> &'call MasterKey {
        self.fleet.workflow().backups().key()
    }

    /// Whether the user may migrate with `router`.
    pub(super) fn may_migrate(self, router: &str) -> bool {
        registry::authorize(self.user.role(), Permission::Migrate, router).is_ok()
    }

    /// Whether `router` names a profile the user may migrate with and sees; checked
    /// before any request to it.
    // cancel-safe: reads only.
    pub(super) async fn permits(self, router: &str) -> bool {
        is_profile_id(router)
            && self.may_migrate(router)
            && matches!(
                lookup(self.fleet, self.user.role(), router).await,
                Ok(Some(_))
            )
    }
}

/// An opened migration, holding its turn until it is dropped.
pub(super) struct Visit<'call> {
    /// The services.
    services: Services<'call>,
    /// The record as stored when the turn was taken.
    record: Record,
    /// The migration's in-memory side.
    session: Arc<Session>,
    /// The migration's turn: no other request reads or writes the record meanwhile.
    _turn: OwnedMutexGuard<()>,
}

impl<'call> Visit<'call> {
    /// Opens migration `id` for the user of `services`, once it is its turn.
    ///
    /// # Errors
    ///
    /// Returns the refusal: a missing or foreign migration is [`Refusal::Missing`], a
    /// router outside the role's `Migrate` scope [`Refusal::Forbidden`].
    // cancel-safe: waits for the turn, then reads.
    pub(super) async fn open(
        services: Services<'call>,
        wizards: &Wizards,
        id: &str,
    ) -> Result<Self, Refusal> {
        if !is_id(id) {
            return Err(Refusal::Missing);
        }
        let session = wizards.session(id);
        let turn = session.turn().await;
        let record = match services.store().load(id) {
            Ok(Some(found)) if found.owner() == services.user().username() => found,
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

    /// The migration's in-memory side.
    pub(super) fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// Writes the record.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(super) fn save(&self) -> Result<(), StoreError> {
        self.services.store().save(&self.record)
    }

    /// Seals `text` as the source configuration.
    ///
    /// # Errors
    ///
    /// Returns sealing and write failures.
    pub(super) fn seal_source(&self, text: &SecretString) -> Result<(), StoreError> {
        self.services
            .store()
            .seal(self.services.key(), self.record.id(), Sealed::Source, text)
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

    /// The analysis of the record's source and target: the kept one, or read again.
    ///
    /// # Errors
    ///
    /// Returns why the source or the target cannot be used.
    // cancel-safe: reads only.
    pub(super) async fn analysis(&self) -> Result<Arc<Analysis>, Problem> {
        let target = self.record.target().ok_or(Problem::Unreachable)?;
        if let Some(kept) = self.session.analysis(target) {
            return Ok(kept);
        }
        let text = self
            .services
            .store()
            .open(self.services.key(), self.record.id(), Sealed::Source)
            .map_err(|error| {
                tracing::error!(%error, "migration source could not be opened");
                Problem::Source
            })?
            .ok_or(Problem::Source)?;
        let fresh = Arc::new(
            Analysis::collect(
                self.services.fleet(),
                self.services.user().role(),
                &self.record,
                &text,
            )
            .await?,
        );
        self.session.keep(target, Arc::clone(&fresh));
        Ok(fresh)
    }

    /// The source router's own inventory, when the source is a router that answers: the
    /// kept one, or read again.
    // cancel-safe: reads only.
    pub(super) async fn hardware(&self, analysis: &Analysis) -> Option<Arc<TargetInventory>> {
        let Some(Source::Router { router }) = self.record.source() else {
            return None;
        };
        if let Some(kept) = self.session.hardware(router) {
            return Some(kept);
        }
        let client = self.services.fleet().registry().client(router).await.ok()?;
        let firmware = analysis.source().firmware;
        match TargetInventory::collect(&InventoryClient::from_client(&client), firmware).await {
            Ok(inventory) => {
                let kept = Arc::new(inventory);
                self.session.keep_hardware(router, Arc::clone(&kept));
                Some(kept)
            }
            Err(error) => {
                tracing::warn!(%error, router, "migration source inventory failed");
                None
            }
        }
    }
}
