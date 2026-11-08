//! The log page's source when the router's log collector runs (`[logs] enabled`).
//!
//! The collector owns the router's one `show log` stream; every viewer reads the
//! collector's latest records and follows its fan-out, so viewers add no router request.

use alloc::collections::BTreeSet;
use core::future::ready;

use futures_util::{
    FutureExt as _, StreamExt as _,
    future::BoxFuture,
    stream::{self, BoxStream},
};
use kcc_domain::{DomainError, RouterCtx};
use kcc_telemetry::logs::{readers::LogFeed, types::LogRecord};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::log_source::{LogSource, new_lines};

/// A collector's records as log lines.
#[derive(Debug, Clone)]
pub(crate) struct CollectorLog {
    /// The router's collector.
    feed: LogFeed,
}

impl CollectorLog {
    /// The lines of the collector behind `feed`.
    pub(crate) const fn new(feed: LogFeed) -> Self {
        Self { feed }
    }
}

impl LogSource for CollectorLog {
    fn tail(&self, _domain: RouterCtx) -> BoxFuture<'static, Result<Vec<String>, DomainError>> {
        ready(Ok(self.feed.recent().iter().map(line).collect())).boxed()
    }

    fn follow(&self, _domain: RouterCtx, seen: Vec<String>) -> BoxStream<'static, Vec<String>> {
        let receiver = self.feed.subscribe();
        let recent = self.feed.recent();
        let shown: BTreeSet<u64> = recent.iter().map(|record| record.id).collect();
        let current: Vec<String> = recent.iter().map(line).collect();
        let opening = stream::iter([new_lines(&seen, &current)]);
        let Some(records) = receiver else {
            return opening.filter(|batch| ready(!batch.is_empty())).boxed();
        };
        let arriving = stream::unfold((records, shown), async |(mut fanout, skip)| {
            let record = next(&mut fanout, &skip).await?;
            Some((vec![line(&record)], (fanout, skip)))
        });
        opening
            .chain(arriving)
            .filter(|batch| ready(!batch.is_empty()))
            .boxed()
    }
}

/// The next record not already in the opening lines; `None` once the collector stopped.
// cancel-safe: `broadcast::Receiver::recv` is cancel-safe.
async fn next(records: &mut Receiver<LogRecord>, shown: &BTreeSet<u64>) -> Option<LogRecord> {
    loop {
        match records.recv().await {
            Ok(record) if shown.contains(&record.id) => {}
            Ok(record) => return Some(record),
            Err(RecvError::Lagged(skipped)) => {
                tracing::debug!(skipped, "log page fell behind the collector");
            }
            Err(RecvError::Closed) => return None,
        }
    }
}

/// One record as a log line: its time, its level label when present, then its message.
fn line(record: &LogRecord) -> String {
    let time = record.ts.format("%b %e %H:%M:%S").to_string();
    [
        Some(time.as_str()),
        record.label.as_deref(),
        Some(&record.message),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}
