//! Stand-ins for the actions, the notifier and the Web accounts.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::sync::{Mutex, PoisonError};

use kcc_app::{accounts::AccountError, brackets::Brackets};
use tokio::{
    sync::{Semaphore, watch},
    time::{sleep, timeout},
};

use super::rig::{TestResult, WAIT};
use crate::server_schedules::{
    actions::{ActionResult, Actions, Call, Running},
    lines::{Line, LineKind},
    notices::Notices,
    owner::{AccountLookup, Lookup},
};

/// Stub actions: busy a number of times, slow for some schedules, held at a gate.
#[derive(Debug, Default)]
pub(crate) struct Stub {
    /// Schedule ids in call order.
    calls: watch::Sender<Vec<String>>,
    /// `start:<id>` and `end:<id>` in order.
    events: Mutex<Vec<String>>,
    /// Busy answers still to give.
    busy: AtomicUsize,
    /// Busy for good.
    always_busy: bool,
    /// How long the action of a schedule takes, virtual time.
    slow: BTreeMap<String, Duration>,
    /// When set, each call holds a bracket guard and waits for a permit.
    gate: Option<(Arc<Semaphore>, Brackets)>,
    /// Calls running now, and the most at once.
    active: (AtomicUsize, AtomicUsize),
}

impl Stub {
    /// Answers busy `times` times, then done.
    pub(crate) fn busy(times: usize) -> Self {
        Self {
            busy: AtomicUsize::new(times),
            ..Self::default()
        }
    }

    /// Always busy.
    pub(crate) fn always_busy() -> Self {
        Self {
            always_busy: true,
            ..Self::default()
        }
    }

    /// Each schedule of `slow` takes its time.
    pub(crate) fn slow(slow: BTreeMap<String, Duration>) -> Self {
        Self {
            slow,
            ..Self::default()
        }
    }

    /// Each call holds a guard of `brackets` until `gate` gives a permit.
    pub(crate) fn gated(gate: Arc<Semaphore>, brackets: Brackets) -> Self {
        Self {
            gate: Some((gate, brackets)),
            ..Self::default()
        }
    }

    /// The schedule ids called so far.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// The start and end events so far.
    pub(crate) fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The most calls that ran at once.
    pub(crate) fn most_at_once(&self) -> usize {
        self.active.1.load(Ordering::SeqCst)
    }

    /// Waits until `count` calls happened.
    pub(crate) async fn called(&self, count: usize) -> TestResult {
        let mut calls = self.calls.subscribe();
        drop(timeout(WAIT, calls.wait_for(|seen| seen.len() >= count)).await??);
        Ok(())
    }

    /// Records `event`.
    fn event(&self, event: String) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }

    /// One call of schedule `id`.
    async fn call(&self, id: String) -> ActionResult {
        self.calls.send_modify(|calls| calls.push(id.clone()));
        let running = self
            .active
            .0
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let _: usize = self.active.1.fetch_max(running, Ordering::SeqCst);
        self.event(format!("start:{id}"));
        if let Some((gate, brackets)) = &self.gate {
            let _open = brackets.enter();
            drop(gate.acquire().await);
        }
        if let Some(wait) = self.slow.get(&id) {
            sleep(*wait).await;
        }
        self.event(format!("end:{id}"));
        let _: usize = self.active.0.fetch_sub(1, Ordering::SeqCst);
        let busy = self.always_busy
            || self
                .busy
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
        if busy {
            ActionResult::Busy
        } else {
            ActionResult::Done {
                unsaved: false,
                checksum: None,
                job: None,
            }
        }
    }
}

impl Actions for Stub {
    fn start<'call>(&'call self, call: Call<'call>) -> Running<'call> {
        let id = call.schedule().id.clone();
        Box::pin(self.call(id))
    }
}

/// Lines, mutes and claimed jobs, recorded.
#[derive(Debug, Default)]
pub(crate) struct Recorder {
    /// Every line.
    lines: watch::Sender<Vec<Line>>,
    /// Every mute: router and until.
    mutes: Mutex<Vec<(String, u64)>>,
    /// Every claimed job id.
    jobs: Mutex<Vec<String>>,
}

impl Recorder {
    /// The kinds of the lines so far, with their schedule ids.
    pub(crate) fn lines(&self) -> Vec<(String, LineKind)> {
        self.lines
            .borrow()
            .iter()
            .map(|line| (line.id().to_owned(), line.kind().clone()))
            .collect()
    }

    /// The mutes so far.
    pub(crate) fn mutes(&self) -> Vec<(String, u64)> {
        self.mutes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The claimed jobs so far.
    pub(crate) fn jobs(&self) -> Vec<String> {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits until `count` lines came.
    pub(crate) async fn received(&self, count: usize) -> TestResult {
        let mut lines = self.lines.subscribe();
        drop(timeout(WAIT, lines.wait_for(|seen| seen.len() >= count)).await??);
        Ok(())
    }
}

impl Notices for Recorder {
    fn send_line(&self, line: Line) {
        self.lines.send_modify(|lines| lines.push(line));
    }

    fn mute_router(&self, router: &str, until: u64) {
        self.mutes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((router.to_owned(), until));
    }

    fn claim_job(&self, id: String) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
    }
}

/// Web accounts by name.
#[derive(Debug, Default)]
pub(crate) struct Accounts(Mutex<BTreeMap<String, Lookup>>);

impl Accounts {
    /// `name` as `lookup` finds it.
    pub(crate) fn set(&self, name: &str, lookup: Lookup) {
        drop(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(name.to_owned(), lookup),
        );
    }
}

impl AccountLookup for Accounts {
    fn find(&self, username: &str) -> Result<Lookup, AccountError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(username)
            .cloned()
            .unwrap_or(Lookup::Missing))
    }
}
