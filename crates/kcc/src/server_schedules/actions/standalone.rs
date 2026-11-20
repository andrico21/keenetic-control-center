//! The actions of a process other than `kcc serve`.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{composition::Core, jobs::JobRunner, persist::StateStore};
use kcc_migrate::{apply::SystemClock, presets::store::PresetStore};

use super::ActionDeps;
use crate::server_schedules::Timings;

/// The actions of a process without a notifier (a CLI run-now) over `core`'s stores in
/// `state`, running their jobs on `jobs`.
pub(in crate::server_schedules) fn deps(
    core: &Core,
    state: &StateStore,
    jobs: Arc<JobRunner>,
) -> ActionDeps {
    ActionDeps {
        registry: Arc::clone(&core.registry),
        workflow: Arc::clone(&core.workflow),
        jobs,
        backups: Arc::clone(&core.backups),
        audit: core.audit.clone(),
        presets: Arc::new(PresetStore::new(state.clone(), core.key.duplicate())),
        notify: None,
        apply_clock: Arc::new(SystemClock::default()),
        timings: Timings::default(),
    }
}
