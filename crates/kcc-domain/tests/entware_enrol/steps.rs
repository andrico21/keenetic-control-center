//! The enrolment steps, callable uniformly for the guard and host tests.

use kcc_domain::{
    RouterCtx,
    entware::ssh::{
        Caller, SshServices,
        enrol::{self, ProbeTicket},
        error::EntwareError,
    },
};
use kcc_testkit::entware_ssh::DEFAULT_PASSWORD;
use tokio::time::timeout;

use crate::{
    harness::{LIMIT, confirm},
    support::TestResult,
};

/// Every enrolment step.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Step {
    /// `probe`.
    Probe,
    /// `bootstrap`.
    Bootstrap,
    /// `repin`.
    Repin,
    /// `revoke`.
    Revoke,
    /// `disable`.
    Disable,
    /// `set_port`.
    SetPort,
    /// `set_enabled`.
    SetEnabled,
}

/// The steps that open an SSH connection.
pub(crate) const SSH_STEPS: [Step; 4] = [Step::Probe, Step::Bootstrap, Step::Repin, Step::Revoke];

/// The local steps.
pub(crate) const LOCAL_STEPS: [Step; 3] = [Step::SetPort, Step::SetEnabled, Step::Disable];

/// The steps that take the router write lease.
pub(crate) const LEASED_STEPS: [Step; 6] = [
    Step::Bootstrap,
    Step::Repin,
    Step::Revoke,
    Step::Disable,
    Step::SetPort,
    Step::SetEnabled,
];

/// One call of a step: who calls it, through which router context, with which ticket.
pub(crate) struct Call<'call> {
    /// The services.
    services: &'call SshServices,
    /// The router context.
    router: &'call RouterCtx,
    /// The caller.
    caller: Caller<'call>,
    /// The probe ticket bootstrap and re-pin redeem.
    ticket: &'call ProbeTicket,
}

impl<'call> Call<'call> {
    /// A call of `caller` through `router` with `ticket`.
    pub(crate) const fn new(
        services: &'call SshServices,
        router: &'call RouterCtx,
        caller: Caller<'call>,
        ticket: &'call ProbeTicket,
    ) -> Self {
        Self {
            services,
            router,
            caller,
            ticket,
        }
    }

    /// Runs `step`, discarding its value.
    // NOT cancel-safe: a dropped bootstrap, re-pin or revoke leaves a half-done state.
    pub(crate) async fn run(&self, step: Step) -> TestResult<Result<(), EntwareError>> {
        let (services, router, caller) = (self.services, self.router, &self.caller);
        let confirmation = confirm(self.ticket, DEFAULT_PASSWORD);
        Ok(match step {
            Step::Probe => timeout(LIMIT, enrol::probe(services, router, caller))
                .await?
                .map(drop),
            Step::Bootstrap => timeout(
                LIMIT,
                enrol::bootstrap(services, router, caller, confirmation),
            )
            .await?
            .map(drop),
            Step::Repin => timeout(LIMIT, enrol::repin(services, router, caller, confirmation))
                .await?
                .map(drop),
            Step::Revoke => timeout(LIMIT, enrol::revoke(services, router, caller)).await?,
            Step::Disable => timeout(LIMIT, enrol::disable(services, caller))
                .await?
                .map(drop),
            Step::SetPort => timeout(LIMIT, enrol::set_port(services, caller, 2222))
                .await?
                .map(drop),
            Step::SetEnabled => timeout(LIMIT, enrol::set_enabled(services, caller, false))
                .await?
                .map(drop),
        })
    }
}
