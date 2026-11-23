//! The per-address registration limiter.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};
use std::sync::{Mutex, PoisonError};

use super::{HOUR, MAX_TRACKED_ADDRESSES, REGISTRATIONS_PER_HOUR, RegistrationLimiter, V6_PREFIX};
use crate::accounts::Clock;

impl fmt::Debug for RegistrationLimiter {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tracked = self
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("RegistrationLimiter")
            .field("tracked", &tracked)
            .finish_non_exhaustive()
    }
}

impl RegistrationLimiter {
    /// A limiter on `clock` that has seen nothing.
    #[inline]
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// Whether a registration from `address` is admitted now; an admitted one counts.
    #[inline]
    #[must_use]
    pub fn admit(&self, address: IpAddr) -> bool {
        let now = self.clock.unix_seconds();
        let key = match address.to_canonical() {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & V6_PREFIX)),
        };
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_address, times| {
            times.retain(|time| now < time.saturating_add(HOUR));
            !times.is_empty()
        });
        let full = !seen.contains_key(&key) && seen.len() >= MAX_TRACKED_ADDRESSES;
        let times = seen.entry(key).or_default();
        let admitted = !full && times.len() < REGISTRATIONS_PER_HOUR;
        if admitted {
            times.push(now);
        }
        drop(seen);
        admitted
    }
}
