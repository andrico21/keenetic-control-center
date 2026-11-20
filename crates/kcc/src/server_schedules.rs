//! Weekly scheduled actions of `kcc serve`.
//!
//! The scheduler starts with the server, after the notifier, and runs nowhere else: not in
//! `kcc mcp stdio` and not in a CLI process. Its timetable follows `schedules.json` (the
//! state watcher tells it about changes made elsewhere) and the router profiles; a slot
//! whose time has come is queued for its router, and each router's runs go one after the
//! other through that router's own queue.
//!
//! A run acts as `system:schedule:<id>` with its owner's authority as it is at run time:
//! a missing, disabled or out-of-scope owner pauses the schedule, and so does a role that
//! lost a permission the action needs. Each slot runs at most once: the run ledger records
//! the run before its first router request, and a slot the ledger has already fired is
//! dropped. A slot more than two minutes late is skipped and reported, never caught up; a
//! busy router is tried again every minute until ten minutes after the slot. Scheduled
//! changes are never saved.
//!
//! [`run::run_once`] is the one run path; a run-now from the Web or the CLI calls it with
//! a `Trigger::Now`, which is never retried.

pub(crate) mod actions;
pub(crate) mod lines;
pub(crate) mod notices;
pub(crate) mod owner;
mod queue;
mod record;
pub(crate) mod run;
mod slots;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;
mod timetable;
pub(crate) mod wiring;

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    accounts::Clock, audit::AuditLog, persist::StateStore, registry::RouterRegistry,
    role_source::RoleSource, settings::CliConfig,
};
use tokio::{sync::watch, task::JoinHandle, time::timeout};
use tokio_util::sync::{CancellationToken, DropGuard};

use self::{actions::Actions, lines::Line, notices::Notices, owner::AccountLookup};
use crate::state_watch::Follower;

/// The state files the scheduler follows, relative to the state directory.
pub(crate) const FILES: &[&str] = &["schedules.json"];

/// Log target of the scheduler's own events.
const TARGET: &str = "kcc::scheduler";

/// How long the scheduler waits for things; shorter in tests.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timings {
    /// Longest sleep between two looks at the wall clock.
    tick_max: Duration,
    /// How late a slot may still start.
    late_limit: Duration,
    /// Wait between two tries on a busy router.
    busy_retry: Duration,
    /// How long after its slot a run may still start on a busy router.
    busy_window: Duration,
    /// Wait between two checks whether a restarted router answers.
    reboot_probe: Duration,
    /// How long a restarted router has to answer again.
    reboot_wait: Duration,
    /// How long a restart mutes the router's offline and online messages.
    reboot_mute: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick_max: Duration::from_secs(30),
            late_limit: Duration::from_secs(120),
            busy_retry: Duration::from_secs(60),
            busy_window: Duration::from_mins(10),
            reboot_probe: Duration::from_secs(15),
            reboot_wait: Duration::from_mins(15),
            reboot_mute: Duration::from_mins(15),
        }
    }
}

/// What a run reads, writes and reports to.
#[derive(Debug)]
pub(crate) struct RunDeps {
    /// The state directory: schedules and the run ledger.
    state: StateStore,
    /// Web accounts, for a Web owner.
    accounts: Arc<dyn AccountLookup>,
    /// The roles in force.
    roles: RoleSource,
    /// `[cli]` of the `kcc.toml` loaded at start, for a CLI owner.
    cli: CliConfig,
    /// This process's audit writer.
    audit: AuditLog,
    /// Wall clock.
    clock: Arc<dyn Clock>,
    /// Where lines go; `None` sends none.
    notices: Option<Arc<dyn Notices>>,
    /// The actions.
    actions: Arc<dyn Actions>,
    /// Waits.
    timings: Timings,
    /// Cancelled at shutdown: no run is admitted and no busy retry starts after it.
    stop: CancellationToken,
}

impl RunDeps {
    /// The wall clock in Unix seconds.
    fn now(&self) -> i64 {
        i64::try_from(self.clock.unix_seconds()).unwrap_or(i64::MAX)
    }

    /// Sends `line` when lines go anywhere.
    fn report(&self, line: Line) {
        if let Some(notices) = &self.notices {
            notices.send_line(line);
        }
    }
}

/// The running scheduler; dropping it stops admission (an early startup failure).
#[derive(Debug)]
pub(crate) struct Scheduler {
    /// Stops admission.
    stop: CancellationToken,
    /// Stops admission when the scheduler is dropped.
    _stop_on_drop: DropGuard,
    /// Asks the timetable to re-read `schedules.json`.
    reloads: Arc<watch::Sender<()>>,
    /// The timetable task; it ends after the runs in progress.
    task: JoinHandle<()>,
}

impl Scheduler {
    /// Starts the timetable over `deps` and the router profiles of `registry`.
    pub(crate) fn start(deps: RunDeps, registry: Arc<RouterRegistry>) -> Self {
        let stop = deps.stop.clone();
        let (reloads, requests) = watch::channel(());
        let task = tokio::spawn(timetable::run(Arc::new(deps), registry, requests));
        Self {
            _stop_on_drop: stop.clone().drop_guard(),
            stop,
            reloads: Arc::new(reloads),
            task,
        }
    }

    /// The token that stops admission; cancelling it twice is harmless.
    pub(crate) fn stop_token(&self) -> CancellationToken {
        self.stop.clone()
    }

    /// The state watcher's follower that reloads the schedules.
    pub(crate) fn follower(&self) -> Arc<dyn Follower> {
        Arc::new(Reloader(Arc::clone(&self.reloads)))
    }

    /// Stops admission and waits at most `grace` for the runs in progress; a run still
    /// going then runs on detached (its bracket guard keeps the server's bracket wait).
    // cancel-safe: only waits; the task is never aborted.
    pub(crate) async fn finish(self, grace: Duration) {
        self.stop.cancel();
        match timeout(grace, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(target: TARGET, %error, "scheduler task failed"),
            Err(_elapsed) => {
                tracing::warn!(target: TARGET, "scheduled runs still going at exit run on");
            }
        }
    }
}

/// Tells the scheduler to reload when `schedules.json` changes.
#[derive(Debug)]
struct Reloader(Arc<watch::Sender<()>>);

impl Follower for Reloader {
    fn reload(&self) {
        self.0.send_replace(());
    }
}
