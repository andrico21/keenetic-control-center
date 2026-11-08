//! Read access to the collectors for in-process readers such as the Web log page.
//!
//! A [`LogFeed`] gives a reader the collector's latest records and a subscription to the
//! new ones, so any number of readers share the router's one `show log` stream instead of
//! each reading the router.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use std::sync::{Mutex, PoisonError};

use tokio::sync::broadcast;

use super::types::LogRecord;

/// Records kept for readers that open after they arrived.
pub(crate) const RECENT_RECORDS: usize = 200;

/// The latest records of one collector, oldest first.
pub(crate) type Recent = Arc<Mutex<VecDeque<LogRecord>>>;

/// One collector's records, as a reader sees them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogFeed {
    /// The collector's fan-out; dead once the collector stops.
    records: broadcast::WeakSender<LogRecord>,
    /// The latest [`RECENT_RECORDS`] records.
    recent: Recent,
}

impl LogFeed {
    /// A feed over a collector's fan-out and recent records.
    pub(crate) fn new(records: &broadcast::Sender<LogRecord>, recent: Recent) -> Self {
        Self {
            records: records.downgrade(),
            recent,
        }
    }

    /// The collector's latest records, oldest first.
    #[inline]
    #[must_use]
    pub fn recent(&self) -> Vec<LogRecord> {
        self.recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Subscribes to the records the collector emits from now on; `None` once the
    /// collector stopped.
    #[inline]
    #[must_use]
    pub fn subscribe(&self) -> Option<broadcast::Receiver<LogRecord>> {
        self.records.upgrade().map(|sender| sender.subscribe())
    }
}

/// The feeds of every running collector, by router id.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LogFeeds(BTreeMap<String, LogFeed>);

impl LogFeeds {
    /// The feeds in `feeds`.
    pub(crate) const fn new(feeds: BTreeMap<String, LogFeed>) -> Self {
        Self(feeds)
    }

    /// The feed of `router`, when a collector follows it.
    #[inline]
    #[must_use]
    pub fn get(&self, router: &str) -> Option<&LogFeed> {
        self.0.get(router)
    }
}

/// Appends `record` to `recent`, dropping the oldest beyond [`RECENT_RECORDS`].
pub(crate) fn remember(recent: &Recent, record: &LogRecord) {
    let mut kept = recent.lock().unwrap_or_else(PoisonError::into_inner);
    if kept.len() >= RECENT_RECORDS {
        drop(kept.pop_front());
    }
    kept.push_back(record.clone());
}
