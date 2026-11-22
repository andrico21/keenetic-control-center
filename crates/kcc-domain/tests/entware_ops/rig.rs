//! Operations rig: an enrolled harness with a small Entware userland, and every operation
//! as a value for table tests.

use kcc_domain::{
    RouterCtx,
    entware::ssh::{
        Caller,
        error::EntwareError,
        ops::{self, PackageChange, ServiceOutcome, ServiceVerb},
    },
};
use kcc_ssh::{
    grammar::{PackageName, ServiceName},
    parse::{Package, ServiceState},
};
use kcc_testkit::{
    entware_ssh::{Config, Counters, Service},
    model::Firmware,
};
use tokio::time::timeout;

use crate::{
    harness::{Harness, LIMIT},
    support::TestResult,
};

/// The fake's userland: two installed packages (one upgradable), one installable, a
/// frozen pair whose package manager changes nothing, and services in every state.
pub(crate) fn userland() -> Config {
    Config::default()
        .installed("nano", "7.2-1")
        .installed("dropbear", "2022.83-1")
        .upgradable("nano", "7.4-1")
        .installable("htop", "3.3.0-1")
        .installed("pinned", "1.0-1")
        .upgradable("pinned", "1.1-1")
        .installable("ghost", "0.1-1")
        .frozen("pinned")
        .frozen("ghost")
        .service("S50nginx", Service::new("nginx"))
        .service("S51dropbear", Service::new("dropbear").running())
        .service("S60idle", Service::new("idle").disabled())
        .service("S61lame", Service::new("lame").disabled().running())
        .service("S70broken", Service::new("broken").failing())
        .service("S71stuck", Service::new("stuck").failing().running())
        .service("S80odd", Service::new("odd").exits(3))
        .service("S81liar", Service::new("liar").failing().exits(0))
        .service("S82liar", Service::new("liar").failing().running().exits(0))
}

/// One operation with its arguments.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Op {
    /// `packages_list`.
    List,
    /// `packages_upgradable`.
    Upgradable,
    /// `update`.
    Update,
    /// `install`.
    Install(&'static str),
    /// `remove`.
    Remove(&'static str),
    /// `upgrade`.
    Upgrade(&'static str),
    /// `services_list`.
    Services,
    /// `service_status`.
    Status(&'static str),
    /// `service_action`.
    Action(&'static str, ServiceVerb),
}

/// The reads.
pub(crate) const READS: [Op; 4] = [
    Op::List,
    Op::Upgradable,
    Op::Services,
    Op::Status("S51dropbear"),
];

/// The mutations, each of which would succeed on a fresh rig.
pub(crate) const MUTATIONS: [Op; 7] = [
    Op::Update,
    Op::Install("htop"),
    Op::Remove("dropbear"),
    Op::Upgrade("nano"),
    Op::Action("S50nginx", ServiceVerb::Start),
    Op::Action("S51dropbear", ServiceVerb::Stop),
    Op::Action("S51dropbear", ServiceVerb::Restart),
];

/// What an operation returned.
#[derive(Debug)]
pub(crate) enum Done {
    /// A package listing.
    Packages(Vec<Package>),
    /// `update`.
    Updated,
    /// A package change.
    Change(PackageChange),
    /// The service listing.
    Services(Vec<ServiceName>),
    /// A service state.
    State(ServiceState),
    /// A service action.
    Outcome(ServiceOutcome),
}

/// `name` as a package name.
pub(crate) fn package(name: &str) -> TestResult<PackageName> {
    Ok(PackageName::parse(name)?)
}

/// `name` as a service name.
pub(crate) fn service(name: &str) -> TestResult<ServiceName> {
    Ok(ServiceName::parse(name)?)
}

/// An enrolled harness over [`userland`].
pub(crate) struct Rig {
    /// The harness.
    harness: Harness,
}

impl Rig {
    /// Starts both fakes on `firmware` with `config` and enrols.
    // NOT cancel-safe: a dropped enrolment leaves the record pending.
    pub(crate) async fn with(firmware: Firmware, config: Config) -> TestResult<Self> {
        let harness = Harness::start(firmware, config).await?;
        drop(harness.enrol().await?);
        Ok(Self { harness })
    }

    /// Starts on 5.1 with [`userland`] and enrols.
    // NOT cancel-safe: a dropped enrolment leaves the record pending.
    pub(crate) async fn start() -> TestResult<Self> {
        Self::with(Firmware::V5_1, userland()).await
    }

    /// The harness.
    pub(crate) const fn harness(&self) -> &Harness {
        &self.harness
    }

    /// Runs `op` as the administrator.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    pub(crate) async fn run(&self, op: Op) -> TestResult<Result<Done, EntwareError>> {
        self.run_as(op, &self.harness.caller()).await
    }

    /// Runs `op` as `caller`.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    pub(crate) async fn run_as(
        &self,
        op: Op,
        caller: &Caller<'_>,
    ) -> TestResult<Result<Done, EntwareError>> {
        self.call(op, caller, self.harness.context()).await
    }

    /// Runs `op` as the administrator through `router`.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    pub(crate) async fn run_via(
        &self,
        op: Op,
        router: &RouterCtx,
    ) -> TestResult<Result<Done, EntwareError>> {
        self.call(op, &self.harness.caller(), router).await
    }

    /// Runs `op` as `caller` through `router`.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    async fn call(
        &self,
        op: Op,
        caller: &Caller<'_>,
        router: &RouterCtx,
    ) -> TestResult<Result<Done, EntwareError>> {
        let services = self.harness.services();
        let call = async {
            Ok(match op {
                Op::List => ops::packages_list(services, router, caller)
                    .await
                    .map(Done::Packages),
                Op::Upgradable => ops::packages_upgradable(services, router, caller)
                    .await
                    .map(Done::Packages),
                Op::Update => ops::update(services, router, caller)
                    .await
                    .map(|()| Done::Updated),
                Op::Install(name) => ops::install(services, router, caller, package(name)?)
                    .await
                    .map(Done::Change),
                Op::Remove(name) => ops::remove(services, router, caller, package(name)?)
                    .await
                    .map(Done::Change),
                Op::Upgrade(name) => ops::upgrade(services, router, caller, package(name)?)
                    .await
                    .map(Done::Change),
                Op::Services => ops::services_list(services, router, caller)
                    .await
                    .map(Done::Services),
                Op::Status(name) => ops::service_status(services, router, caller, service(name)?)
                    .await
                    .map(Done::State),
                Op::Action(name, verb) => {
                    ops::service_action(services, router, caller, service(name)?, verb)
                        .await
                        .map(Done::Outcome)
                }
            })
        };
        timeout(LIMIT, call).await?
    }

    /// Runs `op` as the administrator; it must succeed.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    pub(crate) async fn ok(&self, op: Op) -> TestResult<Done> {
        Ok(self.run(op).await??)
    }

    /// Runs the package mutation `op`; it must succeed.
    // NOT cancel-safe: a dropped mutation may have changed the fake.
    pub(crate) async fn change(&self, op: Op) -> TestResult<PackageChange> {
        match self.ok(op).await? {
            Done::Change(change) => Ok(change),
            other @ (Done::Packages(_)
            | Done::Updated
            | Done::Services(_)
            | Done::State(_)
            | Done::Outcome(_)) => Err(format!("{op:?} returned {other:?}").into()),
        }
    }

    /// Runs the service action `op`; it must succeed.
    // NOT cancel-safe: a dropped action may have changed the fake.
    pub(crate) async fn outcome(&self, op: Op) -> TestResult<ServiceOutcome> {
        match self.ok(op).await? {
            Done::Outcome(outcome) => Ok(outcome),
            other @ (Done::Packages(_)
            | Done::Updated
            | Done::Change(_)
            | Done::Services(_)
            | Done::State(_)) => Err(format!("{op:?} returned {other:?}").into()),
        }
    }

    /// Connections, key offers and password attempts since `before`: an operation that
    /// keeps to one session signs in once, with its key.
    pub(crate) fn logins_since(&self, before: Counters) -> TestResult<(u64, u64, u64)> {
        let now = self.harness.counters()?;
        Ok((
            now.connections.saturating_sub(before.connections),
            now.key_offers.saturating_sub(before.key_offers),
            now.password_attempts
                .saturating_sub(before.password_attempts),
        ))
    }

    /// SSH commands the fake received so far.
    pub(crate) fn commands(&self) -> TestResult<u64> {
        Ok(self.harness.counters()?.commands)
    }
}
