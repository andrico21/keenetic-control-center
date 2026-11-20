//! The running scheduler as the Web UI's scheduled actions page drives it.
//!
//! [`Control`] answers the page's three questions. `check` is [`eligible::check`] with the
//! clicker's role. `run_now` re-reads the schedule as the clicker sees it, checks the
//! clicker's authority the same way, and starts [`run::run_once`] with a `Trigger::Now`
//! in the background over the server's own run dependencies, so the run is recorded,
//! audited as `schedule.run` with `requested_by` and reported like a slot's run, and its
//! owner's authority is checked again at admission. `next_slots` reads the state files.
//!
//! A busy router is not refused up front: nothing tells whether a router's lease or
//! write-job slot is taken without taking it. The run then ends `Skipped router_busy`
//! (a run-now is never retried), which the page's last-run column and the message show.
//!
//! The runs it starts are tracked by [`Runs`], which [`super::Scheduler::finish`] closes:
//! it waits for them within the scheduler's grace and then leaves any still going to run
//! on detached, as it does with the timetable; no run is ever aborted.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    permissions::Role,
    persist::StateStore,
    schedules::{
        ledger::{RunsDocument, Trigger},
        model::{Schedule, ScheduleState},
        store::{ScheduleError, ScheduleStore, SchedulesDocument},
    },
};
use kcc_web::admin_scheduled::{
    Checked, RunNow, RunNowStarted, ScheduleControl, ScheduleDraft, ScheduleRefusal,
};
use tokio::{
    task::{JoinError, JoinSet, spawn_blocking},
    time::timeout,
};

use super::{
    RunDeps, TARGET,
    actions::ActionDeps,
    eligible::{self, Draft},
    run,
};

/// The scheduler as the Web UI drives it.
#[derive(Debug)]
pub(super) struct Control {
    /// The server's actions, for the eligibility check.
    actions: ActionDeps,
    /// The server's run dependencies.
    deps: Arc<RunDeps>,
    /// The runs started now.
    runs: Runs,
}

impl Control {
    /// The control over the server's `actions` and run `deps`, tracking its runs in `runs`.
    pub(super) const fn new(actions: ActionDeps, deps: Arc<RunDeps>, runs: Runs) -> Self {
        Self {
            actions,
            deps,
            runs,
        }
    }

    /// Schedule `id` as `role` sees it.
    ///
    /// # Errors
    ///
    /// [`ScheduleRefusal::Forbidden`] for a schedule the role may not see,
    /// [`ScheduleRefusal::Unavailable`] when the schedules cannot be read.
    // cancel-safe: it only reads local state on a blocking thread.
    async fn visible(&self, role: &Role, id: &str) -> Result<Schedule, ScheduleRefusal> {
        let store = ScheduleStore::new(self.deps.state.clone());
        let (reader, wanted) = (role.clone(), id.to_owned());
        match spawn_blocking(move || store.get(&reader, &wanted)).await {
            Ok(Ok(schedule)) => Ok(schedule),
            Ok(Err(ScheduleError::Forbidden | ScheduleError::NotFound)) => {
                Err(ScheduleRefusal::Forbidden)
            }
            Ok(Err(error)) => {
                tracing::warn!(target: TARGET, %error, "a schedule cannot be read for a run-now");
                Err(ScheduleRefusal::Unavailable)
            }
            Err(error) => {
                tracing::warn!(target: TARGET, %error, "a schedule read for a run-now did not finish");
                Err(ScheduleRefusal::Unavailable)
            }
        }
    }
}

impl ScheduleControl for Control {
    // NOT cancel-safe: the check may sign in to the router, and a sign-in dropped mid-way can
    // leave an orphaned router session.
    fn check<'call>(&'call self, role: &'call Role, draft: &'call ScheduleDraft) -> Checked<'call> {
        Box::pin(async move {
            let drafted = Draft::new(&draft.router, &draft.action);
            eligible::check(&self.actions, role, &drafted)
                .await
                .map_err(refusal)
        })
    }

    // NOT cancel-safe: the check may sign in to the router; once started, the run goes on in
    // the background whether or not the future is dropped.
    fn run_now<'call>(
        &'call self,
        role: &'call Role,
        actor: &'call str,
        id: &'call str,
    ) -> RunNow<'call> {
        Box::pin(async move {
            if self.deps.stop.is_cancelled() {
                return Err(ScheduleRefusal::Unavailable);
            }
            let schedule = self.visible(role, id).await?;
            let drafted = Draft::new(&schedule.router, &schedule.action);
            drop(
                eligible::check(&self.actions, role, &drafted)
                    .await
                    .map_err(refusal)?,
            );
            let deps = Arc::clone(&self.deps);
            let trigger = Trigger::Now {
                requested_by: actor.to_owned(),
            };
            let started = self.runs.spawn(async move {
                drop(run::run_once(&deps, &schedule.id, trigger).await);
            });
            if started {
                Ok(RunNowStarted::new())
            } else {
                Err(ScheduleRefusal::Unavailable)
            }
        })
    }

    fn next_slots(&self) -> BTreeMap<String, (String, i64)> {
        upcoming(&self.deps.state, self.deps.now())
    }
}

/// The page's refusal for `found`.
fn refusal(found: eligible::ScheduleRefusal) -> ScheduleRefusal {
    closest(
        found.code(),
        matches!(found, eligible::ScheduleRefusal::Preset(_)),
    )
}

/// The page's refusal of `code`; a code the page does not know reads as the preset being
/// unavailable for a `preset` refusal and as forbidden otherwise.
fn closest(code: &str, preset: bool) -> ScheduleRefusal {
    ScheduleRefusal::from_code(code).unwrap_or(if preset {
        ScheduleRefusal::PresetUnavailable
    } else {
        ScheduleRefusal::Forbidden
    })
}

/// The earliest next slot after `now` among each router's active schedules: router id to
/// the schedule's name and the slot, Unix seconds.
///
/// A schedule's next slot follows its last fired slot and its last change; a slot not
/// after `now` has run or was missed. State that cannot be read reads as no schedules.
pub(super) fn upcoming(state: &StateStore, now: i64) -> BTreeMap<String, (String, i64)> {
    let schedules = state
        .read::<SchedulesDocument>()
        .inspect_err(|error| tracing::warn!(target: TARGET, %error, "schedules cannot be read"))
        .unwrap_or_default()
        .unwrap_or_default()
        .schedules;
    let fired = state
        .read::<RunsDocument>()
        .inspect_err(
            |error| tracing::warn!(target: TARGET, %error, "the run ledger cannot be read"),
        )
        .unwrap_or_default()
        .unwrap_or_default()
        .schedules;
    let mut next = BTreeMap::new();
    for schedule in schedules {
        if schedule.state != ScheduleState::Active {
            continue;
        }
        let last = fired
            .get(&schedule.id)
            .and_then(|runs| runs.last_fired_slot)
            .unwrap_or(i64::MIN);
        let after = last.max(schedule.updated_at).max(now);
        let Some(slot) = schedule.when.next_slot_unix(after) else {
            continue;
        };
        let earlier = next
            .get(&schedule.router)
            .is_none_or(|&(_, known): &(String, i64)| slot < known);
        if earlier {
            drop(next.insert(schedule.router, (schedule.name.as_str().to_owned(), slot)));
        }
    }
    next
}

/// The runs started now, until the scheduler finishes.
#[derive(Clone, Debug)]
pub(super) struct Runs(Arc<Mutex<Option<Detached>>>);

/// Tasks that run on detached when the set is dropped, never aborted.
#[derive(Debug, Default)]
struct Detached(JoinSet<()>);

impl Drop for Detached {
    fn drop(&mut self) {
        self.0.detach_all();
    }
}

impl Runs {
    /// No run yet; runs are admitted until [`Self::close`].
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Some(Detached::default()))))
    }

    /// Starts `run` and tracks it; `false` once closed.
    fn spawn<F>(&self, run: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(set) = open.as_mut() else {
            return false;
        };
        while let Some(ended) = set.0.try_join_next() {
            failed(ended);
        }
        drop(set.0.spawn(run));
        drop(open);
        true
    }

    /// Admits no run after it and waits at most `grace` for the runs still going; any
    /// still going then runs on detached.
    // cancel-safe: dropped while it waits, the runs still going run on detached.
    pub(super) async fn close(&self, grace: Duration) {
        let taken = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        let Some(mut set) = taken else {
            return;
        };
        let joined = timeout(grace, async {
            while let Some(ended) = set.0.join_next().await {
                failed(ended);
            }
        })
        .await;
        if joined.is_err() {
            tracing::warn!(target: TARGET, "runs started now still going at exit run on");
        }
    }
}

/// Logs a run that panicked.
fn failed(ended: Result<(), JoinError>) {
    if let Err(error) = ended {
        tracing::error!(target: TARGET, %error, "a run started now failed");
    }
}
