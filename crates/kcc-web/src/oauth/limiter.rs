//! The per-address limit on authorization requests, in front of the pending store's own
//! per-source share (`MAX_ENTRIES_PER_SOURCE` of `MAX_ENTRIES`).
//!
//! Memory only: no address is ever written to disk or logged.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    accounts::Clock,
    mcp_auth::pending::{REQUEST_LIFETIME_SECONDS, source::address_group},
};

/// Authorization requests admitted per address within [`REQUEST_LIFETIME_SECONDS`].
pub(crate) const AUTHORIZATIONS_PER_WINDOW: usize = 30;

/// Addresses tracked at once; a new address beyond them is refused until some age out.
pub(crate) const MAX_TRACKED_ADDRESSES: usize = 4096;

/// Counts authorization requests per address.
pub(crate) struct AuthorizeLimiter {
    /// The time source.
    clock: Arc<dyn Clock>,
    /// The admission times per address (IPv6 per /64).
    seen: Mutex<BTreeMap<IpAddr, Vec<u64>>>,
}

impl AuthorizeLimiter {
    /// A limiter on `clock` that has seen nothing.
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// Whether an authorization request from `address` is admitted now; an admitted one
    /// counts.
    pub(crate) fn admit(&self, address: IpAddr) -> bool {
        let now = self.clock.unix_seconds();
        let key = address_group(address);
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_address, times| {
            times.retain(|time| now < time.saturating_add(REQUEST_LIFETIME_SECONDS));
            !times.is_empty()
        });
        if !seen.contains_key(&key) && seen.len() >= MAX_TRACKED_ADDRESSES {
            return false;
        }
        let times = seen.entry(key).or_default();
        let admitted = times.len() < AUTHORIZATIONS_PER_WINDOW;
        if admitted {
            times.push(now);
        }
        drop(seen);
        admitted
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicU64, Ordering},
    };

    use kcc_app::{accounts::Clock, mcp_auth::pending::REQUEST_LIFETIME_SECONDS};

    use super::{AUTHORIZATIONS_PER_WINDOW, AuthorizeLimiter, MAX_TRACKED_ADDRESSES};

    /// A clock a test moves.
    #[derive(Debug, Default)]
    struct Manual(AtomicU64);

    impl Clock for Manual {
        fn unix_seconds(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Regression (todo 31): one address gets 30 authorization requests per window.
    ///
    /// Other addresses are unaffected, the /64 of an IPv6 address counts as one, and the
    /// allowance returns once the window passed.
    #[test]
    fn one_address_is_limited_per_window() {
        let clock = Arc::new(Manual::default());
        let limiter = AuthorizeLimiter::new(Arc::<Manual>::clone(&clock));
        let first = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let admitted = (0..=AUTHORIZATIONS_PER_WINDOW)
            .filter(|_| limiter.admit(first))
            .count();
        assert_eq!(admitted, AUTHORIZATIONS_PER_WINDOW);
        assert!(limiter.admit(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
        let block = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last));
        let v6 = (0..=u16::try_from(AUTHORIZATIONS_PER_WINDOW).unwrap_or(u16::MAX))
            .filter(|last| limiter.admit(block(*last)))
            .count();
        assert_eq!(v6, AUTHORIZATIONS_PER_WINDOW, "a /64 counts as one address");
        clock.0.store(REQUEST_LIFETIME_SECONDS, Ordering::SeqCst);
        assert!(limiter.admit(first), "the window passed");
    }

    /// Regression (todo 31, N18): every address of one IPv6 /64 shares one allowance,
    /// another /64 has its own, and an IPv4-mapped IPv6 address shares its IPv4
    /// address's allowance.
    #[test]
    fn a_slash_64_and_a_mapped_address_share_one_allowance() {
        let limiter = AuthorizeLimiter::new(Arc::new(Manual::default()));
        let address = |block: u16, host: u16| {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, block, 0xffff, 0, 0, host))
        };
        let window = u16::try_from(AUTHORIZATIONS_PER_WINDOW).unwrap_or(u16::MAX);
        let one_block = (1..=window.saturating_add(1))
            .filter(|host| limiter.admit(address(1, *host)))
            .count();
        assert_eq!(
            one_block, AUTHORIZATIONS_PER_WINDOW,
            "one /64, one allowance"
        );
        assert!(limiter.admit(address(2, 1)), "another /64 has its own");

        let v4 = Ipv4Addr::new(198, 51, 100, 20);
        let plain = (1..AUTHORIZATIONS_PER_WINDOW)
            .filter(|_| limiter.admit(IpAddr::V4(v4)))
            .count();
        assert_eq!(plain, AUTHORIZATIONS_PER_WINDOW.saturating_sub(1));
        assert!(limiter.admit(IpAddr::V6(v4.to_ipv6_mapped())), "the 30th");
        assert!(!limiter.admit(IpAddr::V4(v4)), "the 31st, mapped or not");
        assert!(!limiter.admit(IpAddr::V6(v4.to_ipv6_mapped())));
    }

    /// Regression (todo 31): at most 4096 addresses are tracked; a new one beyond them is
    /// refused while they are.
    #[test]
    fn the_tracked_addresses_are_bounded() {
        let limiter = AuthorizeLimiter::new(Arc::new(Manual::default()));
        let addresses = u32::try_from(MAX_TRACKED_ADDRESSES).unwrap_or(u32::MAX);
        let admitted = (0..addresses.saturating_add(4))
            .filter(|index| {
                limiter.admit(IpAddr::V4(Ipv4Addr::from_bits(
                    0xC633_6400_u32.saturating_add(*index),
                )))
            })
            .count();
        assert_eq!(admitted, MAX_TRACKED_ADDRESSES);
    }
}
