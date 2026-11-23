//! Where a pending request came from, and which request gives way when the store is full.
//!
//! A source is a keyed SHA-256 of the client's address group (an IPv4 address, or the /64
//! of an IPv6 address) under a random salt drawn once per process: it is kept in memory
//! only, never the address itself, and means nothing outside this process.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

use sha2::{Digest as _, Sha256};

use super::{Entry, MAX_ENTRIES, MAX_ENTRIES_PER_SOURCE};
use crate::mcp_auth::{RandomError, random};

/// IPv6 addresses are counted per /64, the block one host usually controls.
const V6_PREFIX: u128 = !0_u128 << 64_u32;

/// The salt of every source of this process.
static SALT: OnceLock<[u8; 32]> = OnceLock::new();

/// The group `address` is counted in: an IPv4 address (IPv4-mapped IPv6 included) as
/// itself, an IPv6 address as its /64.
#[inline]
#[must_use]
pub const fn address_group(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & V6_PREFIX)),
    }
}

/// The source key of a request from `address`.
///
/// # Errors
///
/// [`RandomError`] when the salt is drawn now and the OS RNG fails.
pub(super) fn source_of(address: IpAddr) -> Result<[u8; 32], RandomError> {
    let salt = if let Some(drawn) = SALT.get() {
        drawn
    } else {
        let fresh = random()?;
        SALT.get_or_init(|| fresh)
    };
    let mut hasher = Sha256::new();
    hasher.update(salt);
    match address_group(address) {
        IpAddr::V4(v4) => {
            hasher.update([4_u8]);
            hasher.update(v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update([6_u8]);
            hasher.update(v6.octets());
        }
    }
    Ok(hasher.finalize().into())
}

/// The position of the held request that gives way to a new one from `source`, if any.
///
/// The oldest request of `source` once it holds [`MAX_ENTRIES_PER_SOURCE`]; else, at
/// [`MAX_ENTRIES`], the oldest request of the source holding the most (between equals,
/// the oldest of them all). `held` is oldest first and holds live requests only.
pub(super) fn evicted(held: &[Entry], source: &[u8; 32]) -> Option<usize> {
    let mut counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for key in held.iter().filter_map(|entry| entry.source) {
        let count = counts.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    if counts
        .get(source)
        .is_some_and(|held_by| *held_by >= MAX_ENTRIES_PER_SOURCE)
    {
        return held.iter().position(|entry| entry.source == Some(*source));
    }
    if held.len() < MAX_ENTRIES {
        return None;
    }
    let most = counts.values().copied().max().unwrap_or_default();
    held.iter()
        .position(|entry| {
            entry
                .source
                .is_some_and(|key| counts.get(&key) == Some(&most))
        })
        .or(Some(0))
}
