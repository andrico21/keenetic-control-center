//! The services a wizard's request uses: the application state, the signed-in user, the
//! fleet, the runs' directory and key, and the `Migrate` scope checks every wizard makes.

use kcc_app::{permissions::Permission, registry, secrets::MasterKey};

use super::store::Store;
use crate::{
    WebState,
    authz::CurrentUser,
    fleet::Fleet,
    overview::is_profile_id,
    page_kit::context::{Refusal, lookup},
};

/// The services a wizard's request uses.
#[derive(Clone, Copy)]
pub(crate) struct Services<'call> {
    /// The application state.
    state: &'call WebState,
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
    pub(crate) fn of(state: &'call WebState, user: &'call CurrentUser) -> Result<Self, Refusal> {
        let fleet = state.fleet().ok_or(Refusal::Unavailable)?;
        Ok(Self { state, user, fleet })
    }

    /// The application state.
    pub(crate) const fn state(self) -> &'call WebState {
        self.state
    }

    /// The signed-in user.
    pub(crate) const fn user(self) -> &'call CurrentUser {
        self.user
    }

    /// Router fleet services.
    pub(crate) const fn fleet(self) -> &'call Fleet {
        self.fleet
    }

    /// The migrations directory.
    pub(crate) fn store(self) -> Store {
        Store::new(self.fleet.workflow().state().dir())
    }

    /// The key sealing the migrations' secrets: the backups' key.
    pub(crate) fn key(self) -> &'call MasterKey {
        self.fleet.workflow().backups().key()
    }

    /// Whether the user may migrate with `router`.
    pub(crate) fn may_migrate(self, router: &str) -> bool {
        registry::authorize(self.user.role(), Permission::Migrate, router).is_ok()
    }

    /// Whether `router` names a profile the user may migrate with and sees; checked
    /// before any request to it.
    // cancel-safe: reads only.
    pub(crate) async fn permits(self, router: &str) -> bool {
        is_profile_id(router)
            && self.may_migrate(router)
            && matches!(
                lookup(self.fleet, self.user.role(), router).await,
                Ok(Some(_))
            )
    }
}
