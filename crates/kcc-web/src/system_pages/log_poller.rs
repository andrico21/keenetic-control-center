//! One poller per router for the log page's live streams.
//!
//! Without a log collector every viewer would read the router's log itself. Viewers
//! instead join the router's [`Lease`]: the first one starts a task that reads the log
//! now and again every [`POLL_INTERVAL`], and publishes the latest lines; each viewer
//! follows what is published. The task ends when the last viewer lets go of its lease, so
//! any number of viewers cost the router one read stream.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::time::Duration;
use std::sync::{Mutex, PoisonError};

use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use kcc_domain::{DomainError, RouterCtx, logging};
use kcc_rci::{LocalCause, RciError, TransportCause};
use tokio::{sync::watch, task::JoinHandle, time::sleep};

use super::log_source::{POLL_INTERVAL, TAIL_LINES, lines, new_lines};

/// What the poller has read so far.
#[derive(Debug, Clone)]
enum Window {
    /// The first read has not finished.
    Pending,
    /// The latest lines.
    Lines(Arc<[String]>),
    /// The first read failed with this error; the next successful one replaces this.
    Failed(Arc<DomainError>),
}

/// A viewer's share of a router's poller; the poller stops when the last one is dropped.
pub(crate) struct Lease {
    /// The latest lines the poller read.
    window: watch::Receiver<Window>,
    /// The poller.
    task: JoinHandle<()>,
}

impl Lease {
    /// Starts a poller that calls `read` now and every `interval`.
    fn start<Read, Fut>(read: Read, interval: Duration) -> Self
    where
        Read: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<String>, DomainError>> + Send,
    {
        let (publish, window) = watch::channel(Window::Pending);
        let task = tokio::spawn(async move {
            let mut warned = None;
            loop {
                match read().await {
                    Ok(found) => {
                        warned = None;
                        drop(publish.send_replace(Window::Lines(found.into())));
                    }
                    Err(error) => {
                        let shown = error.to_string();
                        if warned.as_ref() != Some(&shown) {
                            tracing::warn!(%error, "router log poll failed");
                            warned = Some(shown);
                        }
                        let _modified: bool = publish.send_if_modified(|latest| {
                            let first = matches!(latest, Window::Pending);
                            if first {
                                *latest = Window::Failed(Arc::new(error));
                            }
                            first
                        });
                    }
                }
                sleep(interval).await;
            }
        });
        Self { window, task }
    }

    /// The latest lines, once the poller has read them.
    ///
    /// # Errors
    ///
    /// Returns the failure of the first read, or a worker failure when the poller stopped
    /// before it read anything.
    // cancel-safe: only waits for the published window.
    pub(crate) async fn tail(&self) -> Result<Vec<String>, Arc<DomainError>> {
        let stopped = || {
            Arc::new(DomainError::Rci(RciError::Transport(
                TransportCause::Local(LocalCause::Worker),
            )))
        };
        let mut window = self.window.clone();
        let latest = window
            .wait_for(|latest| !matches!(latest, Window::Pending))
            .await
            .map_err(|_stopped| stopped())?;
        match &*latest {
            Window::Lines(found) => Ok(found.to_vec()),
            Window::Failed(error) => Err(Arc::clone(error)),
            Window::Pending => Err(stopped()),
        }
    }

    /// The lines that arrive after the `seen` ones, in batches. The stream keeps the
    /// poller alive until it is dropped.
    pub(crate) fn follow(self: Arc<Self>, seen: Vec<String>) -> BoxStream<'static, Vec<String>> {
        let start = (self.window.clone(), seen, self);
        let batches = stream::unfold(start, async |(mut window, previous, lease)| {
            loop {
                window.changed().await.ok()?;
                let current = match &*window.borrow_and_update() {
                    Window::Lines(found) => found.to_vec(),
                    Window::Pending | Window::Failed(_) => continue,
                };
                let fresh = new_lines(&previous, &current);
                if !fresh.is_empty() {
                    return Some((fresh, (window, current, lease)));
                }
            }
        });
        batches.boxed()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The routers' pollers that have viewers.
#[derive(Default)]
pub(crate) struct PolledLogs {
    /// Each router's poller while somebody holds it.
    leases: Mutex<BTreeMap<String, Weak<Lease>>>,
}

impl PolledLogs {
    /// Joins `router`'s poller, starting it for the first viewer, which reads through
    /// `domain`.
    pub(crate) fn join(&self, router: &str, domain: &RouterCtx) -> Arc<Lease> {
        let reader = domain.clone();
        self.join_with(
            router,
            move || {
                let context = reader.clone();
                async move {
                    logging::read_log(&context, TAIL_LINES)
                        .await
                        .map(|text| lines(&text))
                }
            },
            POLL_INTERVAL,
        )
    }

    /// Joins `router`'s poller, starting it with `read` every `interval` when none runs.
    fn join_with<Read, Fut>(&self, router: &str, read: Read, interval: Duration) -> Arc<Lease>
    where
        Read: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<String>, DomainError>> + Send,
    {
        let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(live) = leases.get(router).and_then(Weak::upgrade) {
            return live;
        }
        let lease = Arc::new(Lease::start(read, interval));
        drop(leases.insert(router.to_owned(), Arc::downgrade(&lease)));
        lease
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation and fails by panicking"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use futures_util::StreamExt as _;
    use kcc_domain::DomainError;
    use kcc_rci::{DecodeDetail, LocalCause, RciError, TransportCause};
    use kcc_testkit::log_capture;
    use tokio::{
        sync::{Semaphore, mpsc},
        task::yield_now,
        time::advance,
    };

    use super::PolledLogs;

    /// The interval under test.
    const EVERY: Duration = Duration::from_secs(5);

    /// W4-13: viewers of one router share one poller, which reads once per interval and
    /// stops when the last viewer leaves.
    #[tokio::test(start_paused = true)]
    async fn viewers_share_one_poller_that_stops_with_the_last_one() {
        let reads = Arc::new(AtomicUsize::new(0));
        let polls = PolledLogs::default();
        let read = {
            let counter = Arc::clone(&reads);
            move || {
                let count = counter.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                async move { Ok::<_, DomainError>(vec![format!("line {count}")]) }
            }
        };
        let first = polls.join_with("home", read.clone(), EVERY);
        let second = polls.join_with("home", read.clone(), EVERY);
        assert!(Arc::ptr_eq(&first, &second), "one poller per router");
        assert_eq!(first.tail().await.expect("lines"), ["line 1"]);
        assert_eq!(second.tail().await.expect("lines"), ["line 1"]);
        assert_eq!(reads.load(Ordering::SeqCst), 1, "one read for two viewers");

        let mut batches = Arc::clone(&second).follow(vec!["line 1".to_owned()]);
        assert_eq!(batches.next().await.expect("batch"), ["line 2"]);
        assert_eq!(reads.load(Ordering::SeqCst), 2, "one read per interval");

        drop((first, second, batches));
        advance(EVERY * 3).await;
        yield_now().await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "no read after the last left"
        );

        let again = polls.join_with("home", read, EVERY);
        assert_eq!(
            again.tail().await.expect("lines"),
            ["line 3"],
            "a new poller"
        );
    }

    /// The unreadable answer the injected reader fails with.
    fn unreadable() -> DomainError {
        DomainError::UnreadableAnswer(DecodeDetail::new(
            "show log",
            "$.log",
            kcc_rci::DecodeProblem::Missing {
                field: "message".to_owned(),
            },
        ))
    }

    /// Todo 9: a failed poll keeps the router's real error for `tail()` and logs one
    /// WARN however many polls fail the same way; polls run one per permit.
    #[tokio::test]
    async fn a_failing_poller_returns_its_error_and_warns_once() {
        let (captured, _guard) = log_capture::start();
        let gate = Arc::new(Semaphore::new(0));
        let (announce, mut polls) = mpsc::unbounded_channel::<()>();
        let read = {
            let door = Arc::clone(&gate);
            move || {
                let this_door = Arc::clone(&door);
                let this_poll = announce.clone();
                async move {
                    this_poll.send(()).expect("receiver alive");
                    this_door.acquire().await.expect("open gate").forget();
                    Err::<Vec<String>, _>(unreadable())
                }
            }
        };
        let lease = PolledLogs::default().join_with("home", read, Duration::ZERO);
        for _poll in 0_u8..3 {
            polls.recv().await.expect("poll started");
            gate.add_permits(1);
        }
        polls.recv().await.expect("fourth poll started");

        let error = lease.tail().await.expect_err("the poll failed");
        assert_eq!(error.to_string(), unreadable().to_string());
        assert!(
            format!("{error:?}").contains("UnreadableAnswer"),
            "{error:?}"
        );
        let warned = captured.lines_at("WARN");
        assert_eq!(warned.len(), 1, "one WARN over three polls: {warned:?}");
        assert!(
            warned
                .iter()
                .all(|line| line.contains("router log poll failed")),
            "{warned:?}"
        );
    }

    /// Todo 9: a poller that ends before it published anything makes `tail()` return the
    /// worker-stopped transport error.
    #[tokio::test]
    async fn a_stopped_poller_returns_the_worker_error() {
        let read = || pending::<Result<Vec<String>, DomainError>>();
        let lease = PolledLogs::default().join_with("home", read, EVERY);
        lease.task.abort();

        let error = lease.tail().await.expect_err("the poller stopped");

        assert!(
            matches!(
                &*error,
                DomainError::Rci(RciError::Transport(TransportCause::Local(
                    LocalCause::Worker
                )))
            ),
            "{error:?}"
        );
    }
}
