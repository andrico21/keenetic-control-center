//! One request on one run of a wizard: the services, the record, its session, and the
//! checks every handler makes first.
//!
//! The route table already requires what the wizard's pages need; a run is opened only
//! by the account that started it (anyone else gets 404), and only while the role still
//! holds `Migrate` on every router it names (403 otherwise), before any request to a
//! router.

use alloc::{collections::BTreeMap, sync::Arc};

use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::OwnedMutexGuard;

use super::{
    flow::Flow,
    ids::is_id,
    service::{Session, Wizards},
    services::Services,
    store::{Sealed, StoreError},
};
use crate::page_kit::{audit::Record as Audit, context::Refusal};

/// An opened run, holding its turn until it is dropped.
pub(crate) struct Visit<'call, F>
where
    F: Flow,
{
    /// The services.
    services: Services<'call>,
    /// The record as stored when the turn was taken.
    record: F,
    /// The run's in-memory side.
    session: Arc<Session<F>>,
    /// The run's turn: no other request reads or writes the record meanwhile.
    _turn: OwnedMutexGuard<()>,
}

impl<'call, F> Visit<'call, F>
where
    F: Flow,
{
    /// Opens run `id` for the user of `services`, once it is its turn.
    ///
    /// # Errors
    ///
    /// Returns the refusal: a missing or foreign run is [`Refusal::Missing`], a router
    /// outside the role's `Migrate` scope [`Refusal::Forbidden`], audited as the wizard's
    /// `forbidden` run on that router.
    // NOT cancel-safe: the refusal's audit entry may be written after cancellation; before
    // it, the open only waits for the turn and reads.
    pub(crate) async fn open(
        services: Services<'call>,
        wizards: &Wizards<F>,
        id: &str,
    ) -> Result<Self, Refusal> {
        if !is_id(id) {
            return Err(Refusal::Missing);
        }
        let session = wizards.session(id);
        let turn = session.turn().await;
        let record = match services.store().load::<F>(id) {
            Ok(Some(found)) if found.owner() == services.user().username() => found,
            Ok(_) => return Err(Refusal::Missing),
            Err(error) => return Err(Refusal::Failed(Box::new(error))),
        };
        if let Some(router) = record
            .routers()
            .into_iter()
            .find(|router| !services.may_migrate(router))
        {
            Audit::on_router(F::RUN, router, id.to_owned())
                .append(services.state(), services.user(), "forbidden")
                .await;
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
    pub(crate) const fn services(&self) -> Services<'call> {
        self.services
    }

    /// The record.
    pub(crate) const fn record(&self) -> &F {
        &self.record
    }

    /// The record, to change and then [`save`](Self::save).
    pub(crate) const fn record_mut(&mut self) -> &mut F {
        &mut self.record
    }

    /// The run's in-memory side.
    pub(crate) fn session(&self) -> Arc<Session<F>> {
        Arc::clone(&self.session)
    }

    /// Writes the record.
    ///
    /// # Errors
    ///
    /// Returns write failures.
    pub(crate) fn save(&self) -> Result<(), StoreError> {
        self.services.store().save(&self.record)
    }

    /// The typed passwords, by user name.
    ///
    /// # Errors
    ///
    /// Returns read, format and opening failures.
    pub(crate) fn passwords(&self) -> Result<BTreeMap<String, SecretString>, StoreError> {
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
    pub(crate) fn seal_passwords(
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
