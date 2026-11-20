//! The scheduler of `kcc serve`, built from the server's services.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{accounts::AccountStore, settings::Config};
use kcc_web::admin_scheduled::ScheduleControl;
use tokio_util::sync::CancellationToken;

use super::{
    RunDeps, Scheduler, Timings, actions::ActionDeps, notices::Notices, owner::AccountLookup,
};
use crate::{server_notify::NotifyHandle, server_services::Services};

/// Starts the scheduler of `kcc serve` over `services`, reporting through `notify`, with
/// the `[cli]` owner of `config`; also answers the control the Web UI drives it through.
pub(crate) fn start_for_server(
    services: &Services,
    notify: &NotifyHandle,
    config: &Config,
) -> (Scheduler, Arc<dyn ScheduleControl>) {
    let timings = Timings::default();
    let notices: Arc<dyn Notices> = Arc::new(notify.clone());
    let actions = ActionDeps::for_server(services, Some(Arc::clone(&notices)), timings);
    let checks = actions.clone();
    let accounts: Arc<dyn AccountLookup> = Arc::<AccountStore>::clone(&services.accounts);
    let deps = RunDeps {
        state: services.state.clone(),
        accounts,
        roles: services.roles.clone(),
        cli: config.cli.clone(),
        audit: services.audit.clone(),
        clock: Arc::clone(&services.clock),
        notices: Some(notices),
        actions: Arc::new(actions),
        timings,
        stop: CancellationToken::new(),
    };
    let scheduler = Scheduler::start(deps, Arc::clone(&services.registry));
    let control = scheduler.control(checks);
    (scheduler, control)
}
