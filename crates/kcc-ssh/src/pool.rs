//! Session limits: one SSH session per router and four in total.

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::sync::{Mutex, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    error::SshError,
    grammar::RouterId,
    keys::{Auth, HostKeyPin},
    session::Session,
    transport::{self, AdmittedAddresses, PinnedTarget, Timeouts},
};

/// Sessions open at once across all routers.
const GLOBAL_SESSIONS: usize = 4;

/// Sessions open at once to one router.
const ROUTER_SESSIONS: usize = 1;

/// Hands out session slots: a second session to the same router waits for the first to
/// end, and at most four run at once.
#[expect(
    clippy::module_name_repetitions,
    reason = "the pool is named SshPool across the crates that use it"
)]
pub struct SshPool {
    /// The global limit.
    global: Arc<Semaphore>,
    /// The per-router limits, created on first use.
    routers: Mutex<BTreeMap<RouterId, Arc<Semaphore>>>,
}

impl fmt::Debug for SshPool {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPool")
            .field("free", &self.global.available_permits())
            .finish_non_exhaustive()
    }
}

impl Default for SshPool {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SshPool {
    /// A pool with no session open.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(GLOBAL_SESSIONS)),
            routers: Mutex::new(BTreeMap::new()),
        }
    }

    /// Waits for `router`'s slot, then for a global one.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::Protocol`] if a limit was closed, which this pool never does.
    // cancel-safe: dropped while waiting, it leaves the queues; a permit already taken is
    // released with it.
    #[inline]
    pub async fn acquire(&self, router: &RouterId) -> Result<Slot, SshError> {
        let semaphore = {
            let mut routers = self.routers.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                routers
                    .entry(router.clone())
                    .or_insert_with(|| Arc::new(Semaphore::new(ROUTER_SESSIONS))),
            )
        };
        let router_permit = semaphore
            .acquire_owned()
            .await
            .map_err(|_closed| SshError::Protocol)?;
        let global_permit = Arc::clone(&self.global)
            .acquire_owned()
            .await
            .map_err(|_closed| SshError::Protocol)?;
        Ok(Slot {
            _router: router_permit,
            _global: global_permit,
        })
    }
}

/// The right to one connection; released when it, or the [`Session`] it became, drops.
pub struct Slot {
    /// The router's permit.
    _router: OwnedSemaphorePermit,
    /// The global permit.
    _global: OwnedSemaphorePermit,
}

impl fmt::Debug for Slot {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot").finish_non_exhaustive()
    }
}

impl Slot {
    /// Connects to `addresses` without authenticating and returns the ed25519 host key
    /// the server presents, for an admin to confirm before it is pinned.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::UnsupportedHostKey`] for any other key, [`SshError::Connect`]
    /// when no address answers and [`SshError::Timeout`] after `timeouts.connect`.
    // cancel-safe: dropped, the connection is closed; nothing was authenticated or sent.
    #[inline]
    pub async fn probe_host_key(
        self,
        addresses: &AdmittedAddresses,
        timeouts: Timeouts,
    ) -> Result<HostKeyPin, SshError> {
        transport::probe(addresses, timeouts).await
    }

    /// Connects to `target` and authenticates as `root` with `auth`. The handshake ends
    /// before authentication unless the server presents exactly the pinned key.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::HostKeyMismatch`] or [`SshError::UnsupportedHostKey`] for
    /// another host key, [`SshError::AuthRejected`] when the server refuses `auth`,
    /// [`SshError::InvalidKey`] for an unusable private key and [`SshError::Timeout`]
    /// after `timeouts.connect` or `timeouts.auth`.
    // cancel-safe: dropped, the connection is closed; no command was sent.
    #[inline]
    pub async fn connect(
        self,
        target: PinnedTarget,
        auth: Auth,
        timeouts: Timeouts,
    ) -> Result<Session, SshError> {
        let handle = transport::connect(target, &auth, timeouts).await?;
        Ok(Session::new(handle, timeouts, self))
    }
}
