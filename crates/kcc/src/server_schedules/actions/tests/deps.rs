//! Actions over a state directory and router profiles, for tests that bring their own
//! routers.

extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;

use kcc_app::{
    audit::AuditLog, backups::BackupStore, jobs::JobRunner, persist::StateStore,
    registry::RouterRegistry, secrets::MasterKey, workflow::ChangeWorkflow,
};
use kcc_migrate::{apply::Clock as ApplyClock, presets::store::PresetStore};

use crate::server_schedules::{Timings, actions::ActionDeps, notices::Notices};

/// The actions over `state` and the profiles of `registry`, with a fixed master key, a
/// new audit writer and job runner, reporting to `notify` and applying presets on `clock`.
///
/// # Errors
///
/// The audit writer's or the job runner's start error.
// NOT cancel-safe: dropped after the audit writer started, the writer runs on.
pub(crate) async fn actions(
    (state, registry): (&StateStore, Arc<RouterRegistry>),
    notify: Arc<dyn Notices>,
    clock: Arc<dyn ApplyClock>,
) -> Result<ActionDeps, Box<dyn Error>> {
    let key = MasterKey::from_bytes([9_u8; 32]);
    let audit = AuditLog::spawn(state)?;
    let backups = Arc::new(BackupStore::new(state.clone(), key.duplicate()));
    let workflow = ChangeWorkflow::new(
        state.clone(),
        Arc::clone(&registry),
        Arc::clone(&backups),
        audit.clone(),
    );
    let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone()).await?;
    Ok(ActionDeps {
        registry,
        workflow,
        jobs,
        backups,
        audit,
        presets: Arc::new(PresetStore::new(state.clone(), key)),
        notify: Some(notify),
        apply_clock: clock,
        timings: Timings::default(),
    })
}
