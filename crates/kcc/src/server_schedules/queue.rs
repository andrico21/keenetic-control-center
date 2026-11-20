//! One worker and one first-in-first-out queue per router: runs of one router never
//! overlap and start in the order their slots were queued.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::schedules::ledger::Trigger;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};

use super::{RunDeps, TARGET, run::run_once};

/// A queued run: the schedule's id and its slot.
type Queued = (String, i64);

/// One router's worker.
#[derive(Debug)]
struct Worker {
    /// Its queue.
    sender: UnboundedSender<Queued>,
    /// Its task.
    task: JoinHandle<()>,
}

/// The workers of every router that had a run.
#[derive(Debug)]
pub(super) struct Queues {
    /// What runs use.
    deps: Arc<RunDeps>,
    /// Per router id.
    workers: BTreeMap<String, Worker>,
}

impl Queues {
    /// No workers yet.
    pub(super) const fn new(deps: Arc<RunDeps>) -> Self {
        Self {
            deps,
            workers: BTreeMap::new(),
        }
    }

    /// Queues slot `slot` of schedule `id` on `router`.
    pub(super) fn push(&mut self, router: &str, id: String, slot: i64) {
        let worker = self.workers.entry(router.to_owned()).or_insert_with(|| {
            let (sender, receiver) = unbounded_channel();
            let task = tokio::spawn(work(Arc::clone(&self.deps), receiver));
            Worker { sender, task }
        });
        if worker.sender.send((id, slot)).is_err() {
            tracing::warn!(target: TARGET, router, "a router's run queue is closed; the slot is dropped");
        }
    }

    /// Closes every queue and waits until each worker finished its run in progress.
    // cancel-safe: only waits; dropped, the workers run on detached.
    pub(super) async fn close(self) {
        for (router, worker) in self.workers {
            drop(worker.sender);
            if let Err(error) = worker.task.await {
                tracing::error!(target: TARGET, router, %error, "a router's run worker failed");
            }
        }
    }
}

/// Runs `receiver`'s slots one after the other until the stop or the queue's end.
// cancel-safe: a dropped worker loses only runs not yet admitted; see `run_once` for one in
// progress.
async fn work(deps: Arc<RunDeps>, mut receiver: UnboundedReceiver<Queued>) {
    loop {
        let next = tokio::select! {
            biased;
            () = deps.stop.cancelled() => None,
            queued = receiver.recv() => queued,
        };
        let Some((id, slot)) = next else {
            return;
        };
        drop(run_once(&deps, &id, Trigger::Slot(slot)).await);
    }
}
