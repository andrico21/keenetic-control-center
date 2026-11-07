//! Bounded per-router log-id deduplication.

use alloc::collections::{BTreeSet, VecDeque};

/// Default number of recently accepted ids retained per router.
pub const DEFAULT_WINDOW: usize = 10_000;

/// A bounded sliding window of router-assigned log ids.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Window {
    /// Oldest-to-newest accepted ids.
    order: VecDeque<u64>,
    /// Membership index for the bounded window.
    ids: BTreeSet<u64>,
    /// Maximum retained ids.
    capacity: usize,
}

impl Window {
    /// Creates an empty window retaining at most `capacity` ids.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero; capacities are static service configuration.
    #[inline]
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "dedupe capacity must be positive");
        Self {
            order: VecDeque::with_capacity(capacity),
            ids: BTreeSet::new(),
            capacity,
        }
    }

    /// Accepts an unseen id, or a lower id after a gap that signals a router-log reset.
    #[inline]
    pub fn accept(&mut self, id: u64) -> bool {
        if self.ids.contains(&id) {
            return false;
        }
        let reset = self
            .order
            .back()
            .zip(self.order.front())
            .is_some_and(|(&latest, &oldest)| id < oldest && latest.saturating_sub(id) > 1);
        if reset {
            self.order.clear();
            self.ids.clear();
        }
        self.order.push_back(id);
        let _: bool = self.ids.insert(id);
        if self.order.len() > self.capacity
            && let Some(expired) = self.order.pop_front()
        {
            let _: bool = self.ids.remove(&expired);
        }
        true
    }
}

impl Default for Window {
    #[inline]
    fn default() -> Self {
        Self {
            order: VecDeque::with_capacity(DEFAULT_WINDOW),
            ids: BTreeSet::new(),
            capacity: DEFAULT_WINDOW,
        }
    }
}
