//! Bounded batch selection for one log sink worker.

use core::iter;
use std::sync::Mutex;

use super::{pipeline_delivery::lock, queue::Pending, types::LogRecord};

/// Maximum records per request.
pub(super) const MAX_RECORDS: usize = 1_000;
/// Maximum bytes per request.
pub(super) const MAX_BYTES: usize = 0x0010_0000;

/// Why a record was left out of every batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refused {
    /// A request carrying the record alone exceeds [`MAX_BYTES`].
    Oversize,
    /// The record cannot be encoded.
    Unencodable,
}

/// Selects one bounded batch, measuring each record once outside the queue lock.
///
/// Only taking the records happens under the lock. `measure` returns the length of a
/// request that carries the record alone, or `None` when it cannot be encoded. That length
/// includes the request envelope and stream header, so the sum over the batch plus one
/// separator byte per record bounds the real request from above. The record that would
/// cross [`MAX_BYTES`] and every later one go back to the front of the queue; each refused
/// record is reported to `refuse` and left out.
pub(super) fn select<M, R>(queue: &Mutex<Pending>, mut measure: M, mut refuse: R) -> Vec<LogRecord>
where
    M: FnMut(&LogRecord) -> Option<usize>,
    R: FnMut(Refused),
{
    let mut candidates = lock(queue).take(MAX_RECORDS).into_iter();
    let mut batch = Vec::new();
    let mut bytes = 0_usize;
    let mut boundary = None;
    for record in candidates.by_ref() {
        let Some(length) = measure(&record) else {
            refuse(Refused::Unencodable);
            continue;
        };
        if length > MAX_BYTES {
            refuse(Refused::Oversize);
            continue;
        }
        let total = bytes.saturating_add(length).saturating_add(1);
        if total > MAX_BYTES {
            boundary = Some(record);
            break;
        }
        bytes = total;
        batch.push(record);
    }
    if let Some(first) = boundary {
        let rest = iter::once(first).chain(candidates).collect();
        lock(queue).restore_front(rest);
    }
    batch
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, num::NonZeroUsize};
    use std::sync::Mutex;

    use chrono::NaiveDate;

    use super::{MAX_BYTES, select};
    use crate::{
        logs::{queue::Pending, types::LogRecord},
        metrics::instrumentation::SelfMetrics,
    };

    fn queue(count: u64) -> Result<Mutex<Pending>, Box<dyn Error>> {
        let metrics = SelfMetrics::new("batch-unit")?;
        let capacity = NonZeroUsize::new(5_000).ok_or("capacity")?;
        let mut pending = Pending::new("loki-0".to_owned(), capacity, Arc::clone(&metrics));
        let ts = NaiveDate::from_ymd_opt(2026, 11, 7)
            .and_then(|date| date.and_hms_opt(12, 0, 1))
            .ok_or("timestamp")?;
        for id in 0..count {
            pending.push(LogRecord::new(
                "home".to_owned(),
                id,
                ts,
                "info".to_owned(),
                "line".to_owned(),
            ));
        }
        Ok(Mutex::new(pending))
    }

    /// G-13: selection measures each record once, outside the queue lock.
    #[test]
    fn selection_measures_each_record_once_outside_the_lock() -> Result<(), Box<dyn Error>> {
        let pending = queue(1_500)?;
        let mut measured = 0_usize;
        let mut lock_free = true;

        let batch = select(
            &pending,
            |_record| {
                measured = measured.saturating_add(1);
                lock_free &= pending.try_lock().is_ok();
                Some(100)
            },
            |_refused| {},
        );

        assert_eq!(batch.len(), 1_000);
        assert_eq!(measured, 1_000, "one measurement per selected record");
        assert!(lock_free, "the queue lock is free while measuring");
        assert_eq!(
            pending.try_lock().map_err(|_error| "lock")?.records().len(),
            500
        );
        Ok(())
    }

    /// G-13: the record that would cross the byte bound and every later one go back to the
    /// front of the queue in order.
    #[test]
    fn byte_bound_restores_the_rest_in_order() -> Result<(), Box<dyn Error>> {
        let pending = queue(10)?;
        let half = MAX_BYTES.div_euclid(2);

        let batch = select(&pending, |_record| half.checked_sub(1), |_refused| {});

        assert_eq!(
            batch.iter().map(|record| record.id).collect::<Vec<_>>(),
            [0, 1]
        );
        let rest = pending.try_lock().map_err(|_error| "lock")?;
        assert_eq!(
            rest.records().map(|record| record.id).collect::<Vec<_>>(),
            (2..10).collect::<Vec<_>>()
        );
        Ok(())
    }
}
