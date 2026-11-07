//! Bounded pending-record storage for one log sink.

use alloc::{collections::VecDeque, sync::Arc};
use core::num::NonZeroUsize;

use super::types::LogRecord;
use crate::metrics::instrumentation::SelfMetrics;

/// A per-sink queue that retains the newest records when its bound is reached.
#[derive(Debug)]
#[non_exhaustive]
pub struct Pending {
    /// Stable metric label for this destination.
    sink: String,
    /// Hard record bound.
    capacity: NonZeroUsize,
    /// Shared self-metrics registry.
    metrics: Arc<SelfMetrics>,
    /// Records in arrival order.
    records: VecDeque<LogRecord>,
}

impl Pending {
    /// Creates an empty queue for `sink`.
    ///
    /// `capacity` is expected to come from validated [`kcc_app::settings::LogsConfig`].
    #[inline]
    #[must_use]
    pub fn new(sink: String, capacity: NonZeroUsize, metrics: Arc<SelfMetrics>) -> Self {
        Self {
            sink,
            capacity,
            metrics,
            records: VecDeque::with_capacity(capacity.get()),
        }
    }

    /// Adds one record, evicting and counting the oldest record when full.
    #[inline]
    pub fn push(&mut self, record: LogRecord) {
        if self.records.len() == self.capacity.get() {
            drop(self.records.pop_front());
            self.metrics.log_records_dropped(&self.sink, "overflow", 1);
        }
        self.records.push_back(record);
    }

    /// Returns pending records in delivery order.
    #[inline]
    pub fn records(&self) -> impl ExactSizeIterator<Item = &LogRecord> {
        self.records.iter()
    }

    /// Returns whether no records are pending.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Removes the oldest pending record.
    #[inline]
    pub fn pop(&mut self) -> Option<LogRecord> {
        self.records.pop_front()
    }

    /// Restores one record to the front after a batch boundary is found.
    #[inline]
    pub fn restore(&mut self, record: LogRecord) {
        self.records.push_front(record);
    }
}
