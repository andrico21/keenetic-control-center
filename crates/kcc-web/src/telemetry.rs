//! Live router state for the Web UI: one feed per router over the shared poller, and the
//! traffic history computed from its `show interface stat` counters.
//!
//! A feed exists while a page render or an event stream holds it. It keeps one poller
//! subscription; dropping the last holder aborts the feed task, which drops the
//! subscription, so the poller stops after its idle window. Traffic points (one per poll,
//! 15 s apart) live only in memory, at most [`HISTORY_POINTS`] per router covering
//! [`HISTORY_SECONDS`].

extern crate alloc;

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
};
use core::time::Duration;
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_app::poller::{PollResult, Poller, Snapshot};
use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    task::JoinHandle,
    time::{Instant, timeout},
};

use crate::traffic::{TrafficPoint, TrafficSampler};

/// Traffic points kept per router: 30 minutes at the 15-second poll cadence.
pub(crate) const HISTORY_POINTS: usize = 120;

/// Age of the oldest traffic point kept.
pub(crate) const HISTORY_SECONDS: u64 = 1_800;

/// Traffic histories keyed by router id.
type Histories = Arc<Mutex<BTreeMap<String, VecDeque<TrafficPoint>>>>;

/// What a feed publishes after every poll.
#[derive(Debug, Clone, Default)]
pub(crate) struct FeedState {
    /// Whether at least one poll has completed.
    polled: bool,
    /// Whether the latest poll reached the router.
    reachable: bool,
    /// The newest successful snapshot, kept while the router is unreachable.
    snapshot: Option<Snapshot>,
    /// The traffic point of the latest poll, if it produced one.
    point: Option<TrafficPoint>,
}

impl FeedState {
    /// Whether at least one poll has completed.
    pub(crate) const fn polled(&self) -> bool {
        self.polled
    }

    /// Whether the latest poll reached the router.
    pub(crate) const fn reachable(&self) -> bool {
        self.reachable
    }

    /// The newest successful snapshot.
    pub(crate) const fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// The traffic point of the latest poll.
    pub(crate) const fn point(&self) -> Option<TrafficPoint> {
        self.point
    }
}

/// One router's live feed; dropping the last holder stops it.
pub(crate) struct Feed {
    /// The feed's published state.
    updates: watch::Receiver<FeedState>,
    /// The task forwarding poller results.
    task: JoinHandle<()>,
}

impl Feed {
    /// A receiver of this feed's state.
    pub(crate) fn subscribe(&self) -> watch::Receiver<FeedState> {
        self.updates.clone()
    }

    /// The state after the first poll, waiting at most `limit`; the current state when the
    /// poll does not complete in time.
    // cancel-safe: waiting on a cloned watch receiver changes no state.
    pub(crate) async fn first(&self, limit: Duration) -> FeedState {
        let mut receiver = self.updates.clone();
        match timeout(limit, receiver.wait_for(FeedState::polled)).await {
            Ok(Ok(state)) => state.clone(),
            Ok(Err(_)) | Err(_) => self.updates.borrow().clone(),
        }
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The feeds of every router and their traffic histories.
pub(crate) struct Telemetry {
    /// The shared poller.
    poller: Arc<Poller>,
    /// Live feeds; an entry whose feed was dropped is replaced on next use.
    feeds: AsyncMutex<BTreeMap<String, Weak<Feed>>>,
    /// Traffic points per router, kept across feed restarts.
    histories: Histories,
}

impl Telemetry {
    /// No feeds yet.
    pub(crate) fn new(poller: Arc<Poller>) -> Self {
        Self {
            poller,
            feeds: AsyncMutex::new(BTreeMap::new()),
            histories: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The live feed of `router`, subscribing to the poller when none exists.
    // cancel-safe: an abandoned call leaves at most an unused feed that stops when dropped.
    pub(crate) async fn feed(&self, router: &str) -> Arc<Feed> {
        let mut feeds = self.feeds.lock().await;
        if let Some(feed) = feeds.get(router).and_then(Weak::upgrade) {
            return feed;
        }
        feeds.retain(|_, feed| feed.strong_count() > 0);
        let source = self.poller.subscribe(router).await;
        let (sink, updates) = watch::channel(FeedState::default());
        let task = tokio::spawn(run_feed(
            router.to_owned(),
            source,
            sink,
            Arc::clone(&self.histories),
        ));
        let feed = Arc::new(Feed { updates, task });
        drop(feeds.insert(router.to_owned(), Arc::downgrade(&feed)));
        feed
    }

    /// The traffic points of `router`, oldest first.
    pub(crate) fn history(&self, router: &str) -> Vec<TrafficPoint> {
        history_of(&self.histories, router)
    }
}

/// Forwards poller results into the feed state until aborted.
// cancel-safe: aborted only through `Feed::drop`; the task owns all of its state.
async fn run_feed(
    router: String,
    mut source: watch::Receiver<Option<PollResult>>,
    sink: watch::Sender<FeedState>,
    histories: Histories,
) {
    let mut sampler = TrafficSampler::default();
    loop {
        let latest = source.borrow_and_update().clone();
        if let Some(result) = latest {
            let point = match &result {
                Ok(snapshot) => sampler.sample(
                    &snapshot.interface_stats,
                    snapshot.fetched_at,
                    Instant::now(),
                ),
                Err(_poll_error) => {
                    sampler = TrafficSampler::default();
                    None
                }
            };
            if let Some(found) = point {
                record(&histories, &router, found);
            }
            sink.send_modify(|state| {
                state.polled = true;
                state.reachable = result.is_ok();
                state.point = point;
                if let Ok(snapshot) = result {
                    state.snapshot = Some(snapshot);
                }
            });
        }
        if source.changed().await.is_err() {
            return;
        }
    }
}

/// Appends `point` to the history of `router`, keeping it strictly ordered, at most
/// [`HISTORY_POINTS`] long and no older than [`HISTORY_SECONDS`] before `point`.
fn record(histories: &Histories, router: &str, point: TrafficPoint) {
    let mut all = lock(histories);
    let points = all.entry(router.to_owned()).or_default();
    if points.back().is_some_and(|last| last.at() >= point.at()) {
        return;
    }
    let oldest = point.at().saturating_sub(HISTORY_SECONDS);
    points.retain(|kept| kept.at() > oldest);
    points.push_back(point);
    while points.len() > HISTORY_POINTS {
        let _: Option<TrafficPoint> = points.pop_front();
    }
    drop(all);
}

/// The traffic points of `router`, oldest first.
fn history_of(histories: &Histories, router: &str) -> Vec<TrafficPoint> {
    lock(histories)
        .get(router)
        .map_or_default(|points| points.iter().copied().collect())
}

/// The histories; a panic while holding the lock cannot leave a history unordered, so a
/// poisoned lock is used as is.
fn lock(histories: &Histories) -> MutexGuard<'_, BTreeMap<String, VecDeque<TrafficPoint>>> {
    histories.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::{collections::BTreeMap, sync::Arc};
    use std::sync::Mutex;

    use super::{HISTORY_POINTS, Histories, history_of, record};
    use crate::traffic::TrafficPoint;

    /// The history keeps at most 120 increasing points from the last 30 minutes.
    #[test]
    fn history_is_bounded_ordered_and_windowed() {
        let histories: Histories = Arc::new(Mutex::new(BTreeMap::new()));
        for index in 0..130_u64 {
            let point = TrafficPoint::new(index.saturating_mul(15), index, 0);
            record(&histories, "home", point);
        }
        let stale = TrafficPoint::new(15, 1, 1);
        record(&histories, "home", stale);
        let points = history_of(&histories, "home");
        assert_eq!(points.len(), HISTORY_POINTS, "bounded");
        assert!(
            points
                .windows(2)
                .all(|pair| matches!(pair, [older, newer] if older.at() < newer.at())),
            "strictly increasing, the out-of-order point dropped"
        );
        let later = TrafficPoint::new(10_000, 0, 0);
        record(&histories, "home", later);
        assert_eq!(
            history_of(&histories, "home"),
            [later],
            "points older than 30 minutes dropped"
        );
    }
}
