//! The run path of a process other than `kcc serve`: a CLI `run-now`.
//!
//! It runs the server's actions and run path ([`super::run::run_once`]) with this
//! process's own stores, job runner and audit writer. There is no notifier: a run from
//! the command line sends no Telegram message (a running server shows the run on its next
//! ledger read). Nothing here starts the scheduler's timetable, and the stop token is
//! never cancelled, so a run is never cut short by it.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    accounts::{Clock, SystemClock},
    composition::Core,
    jobs::{JobError, JobRunner},
    persist::StateStore,
    role_source::RoleSource,
    settings::CliConfig,
};
use tokio_util::sync::CancellationToken;

use super::{
    RunDeps, Timings,
    actions::{self, ActionDeps},
    owner::AccountLookup,
};

/// Whose authority a run has: the Web accounts, the roles in force and the `[cli]` table
/// of the loaded `kcc.toml` (for a CLI owner).
#[derive(Debug)]
pub(crate) struct Owners {
    /// Web accounts.
    accounts: Arc<dyn AccountLookup>,
    /// The roles in force.
    roles: RoleSource,
    /// `[cli]`.
    cli: CliConfig,
}

impl Owners {
    /// Owners resolved through `accounts`, `roles` and `cli`.
    pub(crate) const fn new(
        accounts: Arc<dyn AccountLookup>,
        roles: RoleSource,
        cli: CliConfig,
    ) -> Self {
        Self {
            accounts,
            roles,
            cli,
        }
    }
}

/// The actions of this process over `core`'s stores in `state`, with a job runner of
/// its own and no notifier.
///
/// # Errors
///
/// The job runner's start error.
// NOT cancel-safe: opening the job runner may sign in first, and a sign-in dropped mid-way can
// leave an orphaned router session.
pub(crate) async fn actions(core: &Core, state: &StateStore) -> Result<ActionDeps, JobError> {
    let jobs = JobRunner::open(
        state.clone(),
        Arc::clone(&core.registry),
        core.audit.clone(),
    )
    .await?;
    Ok(actions::standalone::deps(core, state, jobs))
}

/// The run path over `actions` in `state`, resolving owners through `owners`: no
/// notifier, the wall clock, the server's timings, and a stop token nobody cancels.
pub(crate) fn run_deps(actions: &ActionDeps, state: &StateStore, owners: Owners) -> Arc<RunDeps> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    Arc::new(RunDeps {
        state: state.clone(),
        accounts: owners.accounts,
        roles: owners.roles,
        cli: owners.cli,
        audit: actions.audit().clone(),
        clock,
        notices: None,
        actions: Arc::new(actions.clone()),
        timings: Timings::default(),
        stop: CancellationToken::new(),
    })
}
