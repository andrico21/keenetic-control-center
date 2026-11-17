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

    /// Removes up to `count` of the oldest pending records, in delivery order.
    #[inline]
    pub fn take(&mut self, count: usize) -> Vec<LogRecord> {
        let end = count.min(self.records.len());
        self.records.drain(..end).collect()
    }

    /// Puts `records` taken earlier back at the front, in their order. The bound still holds:
    /// when records pushed meanwhile fill the queue, the oldest restored records are dropped
    /// and counted as overflow.
    #[inline]
    pub fn restore_front(&mut self, records: Vec<LogRecord>) {
        let mut overflow = 0_u64;
        for record in records.into_iter().rev() {
            if self.records.len() < self.capacity.get() {
                self.records.push_front(record);
            } else {
                overflow = overflow.saturating_add(1);
            }
        }
        if overflow > 0 {
            self.metrics
                .log_records_dropped(&self.sink, "overflow", overflow);
        }
    }

    /// Removes every pending record and returns how many there were.
    #[inline]
    pub fn clear(&mut self) -> usize {
        let count = self.records.len();
        self.records.clear();
        count
    }
}
