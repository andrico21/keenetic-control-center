//! Where the log page's lines come from.
//!
//! The page reads the router's log through [`LogSource`]. When the router's log
//! collector runs (`[logs] enabled` and the router selected), it owns the router's one
//! `show log` stream and the page follows it ([`CollectorLog`]) without a request of its
//! own. Otherwise it is [`SharedLog`]: the router's one shared poller (`log_poller`)
//! reads the log (`logging::read_log`, a POST of `show log`) at most every
//! [`POLL_INTERVAL`] for all the viewers, each of whom is shown the lines it has not seen.

use alloc::sync::Arc;
use core::time::Duration;
use std::sync::{Mutex, PoisonError};

use futures_util::{FutureExt as _, future::BoxFuture, stream::BoxStream};
use kcc_domain::{DomainError, RouterCtx};
use serde_json::Value;

use super::{
    log_collector::CollectorLog,
    log_poller::{Lease, PolledLogs},
};
use crate::WebState;

/// How often the shared poller asks the router again; the router's log must not be polled
/// faster than this.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Lines a page shows and each poll asks for.
pub(crate) const TAIL_LINES: u32 = 200;

/// The router's log, as the log page reads it.
pub(crate) trait LogSource: Send + Sync {
    /// The latest lines of the router of `domain`, oldest first.
    fn tail(&self, domain: RouterCtx) -> BoxFuture<'static, Result<Vec<String>, DomainError>>;

    /// The router's new lines as they arrive, in batches, after the `seen` ones.
    fn follow(&self, domain: RouterCtx, seen: Vec<String>) -> BoxStream<'static, Vec<String>>;
}

/// The log source of a router no collector follows: the router's shared poller.
pub(crate) struct SharedLog {
    /// Every router's pollers.
    polls: Arc<PolledLogs>,
    /// The router.
    router: String,
    /// This viewer's share of the router's poller, once joined.
    lease: Mutex<Option<Arc<Lease>>>,
}

impl SharedLog {
    /// A viewer of `router`'s log through `polls`.
    pub(crate) const fn new(polls: Arc<PolledLogs>, router: String) -> Self {
        Self {
            polls,
            router,
            lease: Mutex::new(None),
        }
    }

    /// This viewer's share of the router's poller, joining it on first use.
    fn lease(&self, domain: &RouterCtx) -> Arc<Lease> {
        let mut held = self.lease.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(held.get_or_insert_with(|| self.polls.join(&self.router, domain)))
    }
}

impl LogSource for SharedLog {
    fn tail(&self, domain: RouterCtx) -> BoxFuture<'static, Result<Vec<String>, DomainError>> {
        let lease = self.lease(&domain);
        async move { lease.tail().await }.boxed()
    }

    fn follow(&self, domain: RouterCtx, seen: Vec<String>) -> BoxStream<'static, Vec<String>> {
        self.lease(&domain).follow(seen)
    }
}

/// The log source the page reads for `router`: its running collector, else polling.
pub(crate) fn source(state: &WebState, router: &str) -> Arc<dyn LogSource> {
    match state
        .log_feeds()
        .get(router)
        .filter(|feed| feed.subscribe().is_some())
    {
        Some(feed) => Arc::new(CollectorLog::new(feed.clone())),
        None => Arc::new(SharedLog::new(
            Arc::clone(state.polled_logs()),
            router.to_owned(),
        )),
    }
}

/// The lines of a log answer: plain text line by line, or the records of a JSON `log`
/// object in id order, each as its level label and message.
pub(crate) fn lines(text: &str) -> Vec<String> {
    let Ok(Value::Object(answer)) = serde_json::from_str::<Value>(text) else {
        return text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect();
    };
    let Some(Value::Object(records)) = answer.get("log") else {
        return vec![text.to_owned()];
    };
    let mut ordered: Vec<(u64, String)> = records
        .iter()
        .filter_map(|(id, record)| Some((id.parse().ok()?, record_line(record))))
        .collect();
    ordered.sort_by_key(|(id, _)| *id);
    ordered.into_iter().map(|(_, line)| line).collect()
}

/// One log record as a line: its time and level label when present, then its message.
fn record_line(record: &Value) -> String {
    let message = record.get("message");
    let text = message
        .and_then(|inner| inner.get("message").or(Some(inner)))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let label = message
        .and_then(|inner| inner.get("label"))
        .and_then(Value::as_str);
    let time = record
        .get("timestamp")
        .or_else(|| record.get("time"))
        .and_then(Value::as_str);
    [time, label, Some(text)]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The lines of `current` after the longest run that ends `previous` and starts
/// `current`; everything when they share nothing (the router cleared its log).
pub(crate) fn new_lines(previous: &[String], current: &[String]) -> Vec<String> {
    let longest = previous.len().min(current.len());
    let overlap = (1..=longest)
        .rev()
        .find(|length| {
            previous
                .get(previous.len().saturating_sub(*length)..)
                .zip(current.get(..*length))
                .is_some_and(|(tail, head)| tail == head)
        })
        .unwrap_or(0);
    current.get(overlap..).map_or_default(<[String]>::to_vec)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{lines, new_lines};

    /// `text` as owned lines.
    fn owned(text: &[&str]) -> Vec<String> {
        text.iter().map(|line| (*line).to_owned()).collect()
    }

    #[test]
    fn only_the_lines_after_the_overlap_are_new() {
        let previous = owned(&["a", "b", "c"]);
        assert_eq!(
            new_lines(&previous, &owned(&["b", "c", "d", "e"])),
            ["d", "e"],
            "the window moved"
        );
        assert!(
            new_lines(&previous, &owned(&["a", "b", "c"])).is_empty(),
            "nothing new"
        );
        assert_eq!(
            new_lines(&previous, &owned(&["x"])),
            ["x"],
            "the log was cleared"
        );
        assert_eq!(new_lines(&[], &owned(&["a"])), ["a"], "first read");
    }

    #[test]
    fn text_and_json_answers_become_lines() {
        assert_eq!(lines("one\n\ntwo\n"), ["one", "two"], "text");
        let json = r#"{"log":{"12":{"message":{"label":"W","message":"later"}},"9":{"timestamp":"Jan 1 00:00:01","message":{"label":"I","message":"first"}}}}"#;
        assert_eq!(
            lines(json),
            ["Jan 1 00:00:01 I first", "W later"],
            "records in id order"
        );
    }
}
