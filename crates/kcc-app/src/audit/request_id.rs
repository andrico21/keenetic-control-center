//! Correlation request ids, unique within a process and across processes.
//!
//! An id is `<prefix>-<nonce>-<sequence>`: the nonce is 16 lowercase hex digits drawn
//! once per process from the standard library's randomly keyed hasher (seeded by the
//! operating system), and the sequence counts the ids this process handed out, from 1.
//! Two ids of one process differ in their sequence; ids of two processes differ in their
//! nonce. Nothing in an id comes from the clock.

use core::{
    hash::BuildHasher as _,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{hash::RandomState, process, sync::OnceLock};

/// This process's nonce.
static NONCE: OnceLock<u64> = OnceLock::new();
/// The last sequence number handed out.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A new request id starting with `prefix`, such as `web`, `mcp`, `cli` or `change`.
#[inline]
#[must_use]
pub fn next(prefix: &str) -> String {
    let nonce = NONCE.get_or_init(|| RandomState::new().hash_one(process::id()));
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    format!("{prefix}-{nonce:016x}-{sequence}")
}
