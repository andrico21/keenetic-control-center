//! Entware package and service operations over the router's pinned, key-only SSH session.
//!
//! Every operation needs `Permission::Destructive` on the router (reads included), an
//! Active enrolment with SSH management switched on and the enrolled router host, and
//! `opkg chroot` off; it then opens one session pinned to the enrolled host key and runs
//! only commands of kcc-ssh's closed set. Mutations hold the router write lease and run
//! under the mutation timeout, reads take no lease and run under the read timeout.
//! Removals, upgrades and service operations name a package or service the same session
//! listed first; every mutation is read back. Callers receive parsed values only; the
//! audit entry records the output's byte count and SHA-256, never the output.

pub mod job;
pub mod names;
mod packages;
mod services;
mod session;

use kcc_app::workflow::Reservation;
use kcc_ssh::{
    command::EntwareCommand,
    grammar::{PackageName, ServiceAction, ServiceName},
    parse::{Package, ServiceState},
    session::{Output, Session},
};
use sha2::{Digest as _, Sha256};

use super::{Caller, Facts, SshServices, error::EntwareError, preflight, report::Action};
use crate::RouterCtx;

/// A service action kcc runs: rc.func's `start`, `stop` or `restart`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceVerb {
    /// `start`; `check` must read Running afterwards.
    Start,
    /// `stop`; `check` must read Stopped afterwards.
    Stop,
    /// `restart`; `check` must read Running afterwards.
    Restart,
}

impl ServiceVerb {
    /// The rc.func action.
    const fn action(self) -> ServiceAction {
        match self {
            Self::Start => ServiceAction::Start,
            Self::Stop => ServiceAction::Stop,
            Self::Restart => ServiceAction::Restart,
        }
    }

    /// The audited operation.
    const fn audited(self) -> Action {
        match self {
            Self::Start => Action::ServiceStart,
            Self::Stop => Action::ServiceStop,
            Self::Restart => Action::ServiceRestart,
        }
    }
}

/// A read-back package change: the installed version before and after.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackageChange {
    /// The package.
    pub package: PackageName,
    /// Installed version before the change; `None` when it was not installed.
    pub before: Option<String>,
    /// Installed version read back after the change; `None` when it is not installed.
    pub after: Option<String>,
}

/// How rc.func reported a service action whose `check` read-back succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionExit {
    /// Exit 0.
    Done,
    /// `stop` exit 1: the service was not running.
    AlreadyStopped,
    /// Another status; the `check` read-back decided the outcome.
    Other(u32),
}

/// A service action read back with `check`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceOutcome {
    /// The service.
    pub service: ServiceName,
    /// The state `check` read after the action.
    pub state: ServiceState,
    /// How rc.func reported the action.
    pub exit: ActionExit,
}

/// The installed packages with their versions.
///
/// # Errors
/// [`EntwareError::PermissionDenied`] before any request; the enrolment, SSH-switch,
/// router-host and chroot refusals before any connection; SSH, state, audit or router read
/// failures.
// NOT cancel-safe: the chroot read may sign in first, and the audit entry may be appended
// after cancellation.
#[inline]
pub async fn packages_list(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<Vec<Package>, EntwareError> {
    let mut run = Run::new(services, caller, Action::PackagesList);
    let outcome = Box::pin(packages::listing(&mut run, router, false)).await;
    run.finish(outcome).await
}

/// The installed packages that have an upgrade, with the offered version.
///
/// # Errors
/// As [`packages_list`].
// NOT cancel-safe: as `packages_list`.
#[inline]
pub async fn packages_upgradable(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<Vec<Package>, EntwareError> {
    let mut run = Run::new(services, caller, Action::PackagesUpgradable);
    let outcome = Box::pin(packages::listing(&mut run, router, true)).await;
    run.finish(outcome).await
}

/// Updates the package lists (`opkg update`) under the router write lease.
///
/// # Errors
/// As [`packages_list`], a busy lease ([`EntwareError::Workflow`]), and
/// [`kcc_ssh::error::SshError::UnexpectedOutput`] for a non-zero exit.
// NOT cancel-safe: dropped while the command runs, the router may finish the update.
#[inline]
pub async fn update(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<(), EntwareError> {
    let mut run = Run::new(services, caller, Action::Update);
    let outcome = Box::pin(packages::update(&mut run, router)).await;
    run.finish(outcome).await
}

/// Installs `package` and reads it back from the installed listing.
///
/// # Errors
/// As [`update`], and a verification failure naming the package when it is not
/// installed afterwards.
// NOT cancel-safe: dropped while the command runs, the router may finish the install.
#[inline]
pub async fn install(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    package: PackageName,
) -> Result<PackageChange, EntwareError> {
    let mut run = Run::new(services, caller, Action::Install);
    let outcome = Box::pin(packages::change(
        &mut run,
        router,
        packages::Change::Install(package),
    ))
    .await;
    run.finish(outcome).await
}

/// Removes the installed `package` and reads its absence back.
///
/// # Errors
/// As [`update`], [`EntwareError::PackageNotInstalled`] before any mutating command, and
/// a verification failure naming the package when it is still installed afterwards.
// NOT cancel-safe: dropped while the command runs, the router may finish the removal.
#[inline]
pub async fn remove(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    package: PackageName,
) -> Result<PackageChange, EntwareError> {
    let mut run = Run::new(services, caller, Action::Remove);
    let outcome = Box::pin(packages::change(
        &mut run,
        router,
        packages::Change::Remove(package),
    ))
    .await;
    run.finish(outcome).await
}

/// Upgrades the installed `package` and reads back the version the upgradable listing
/// offered (the installed one when none was offered).
///
/// # Errors
/// As [`remove`].
// NOT cancel-safe: dropped while the command runs, the router may finish the upgrade.
#[inline]
pub async fn upgrade(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    package: PackageName,
) -> Result<PackageChange, EntwareError> {
    let mut run = Run::new(services, caller, Action::Upgrade);
    let outcome = Box::pin(packages::change(
        &mut run,
        router,
        packages::Change::Upgrade(package),
    ))
    .await;
    run.finish(outcome).await
}

/// The init scripts in `/opt/etc/init.d`.
///
/// # Errors
/// As [`packages_list`].
// NOT cancel-safe: as `packages_list`.
#[inline]
pub async fn services_list(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<Vec<ServiceName>, EntwareError> {
    let mut run = Run::new(services, caller, Action::ServicesList);
    let outcome = Box::pin(services::listing(&mut run, router)).await;
    run.finish(outcome).await
}

/// The listed `service`'s state, as rc.func's `check` reports it.
///
/// # Errors
/// As [`packages_list`], and [`EntwareError::UnknownService`] before `check`.
// NOT cancel-safe: as `packages_list`.
#[inline]
pub async fn service_status(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    service: ServiceName,
) -> Result<ServiceState, EntwareError> {
    let mut run = Run::new(services, caller, Action::ServiceStatus);
    let outcome = Box::pin(services::status(&mut run, router, service)).await;
    run.finish(outcome).await
}

/// Runs `verb` on the listed `service` under the router write lease and reads the state
/// back with `check`: Running after start and restart, Stopped after stop.
///
/// Exit 8 is [`EntwareError::ServiceDisabled`] and exit 255 a failure by themselves; any
/// other status leaves the outcome to the read-back.
///
/// # Errors
/// As [`update`], [`EntwareError::UnknownService`] before any action,
/// [`EntwareError::ServiceDisabled`], [`kcc_ssh::error::SshError::ServiceFailed`], and a
/// verification failure naming the service when `check` reads the other state.
// NOT cancel-safe: dropped while the action runs, the service may still change state.
#[inline]
pub async fn service_action(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
    service: ServiceName,
    verb: ServiceVerb,
) -> Result<ServiceOutcome, EntwareError> {
    let mut run = Run::new(services, caller, verb.audited());
    let outcome = Box::pin(services::action(&mut run, router, service, verb)).await;
    run.finish(outcome).await
}

/// One audited operation: its caller, its facts and the digest of its output.
struct Run<'run> {
    /// The services.
    services: &'run SshServices,
    /// Who runs the operation.
    caller: &'run Caller<'run>,
    /// What the audit entry records.
    facts: Facts,
    /// SHA-256 and byte count of every output received, once a command ran.
    digest: Option<(Sha256, u64)>,
}

impl<'run> Run<'run> {
    /// A run of `action` by `caller`.
    const fn new(services: &'run SshServices, caller: &'run Caller<'run>, action: Action) -> Self {
        Self {
            services,
            caller,
            facts: Facts::new(action),
            digest: None,
        }
    }

    /// Admits a read: the permission and a live audit writer; no lease.
    ///
    /// # Errors
    /// [`EntwareError::PermissionDenied`] or [`EntwareError::Audit`].
    fn read(&self) -> Result<(), EntwareError> {
        preflight::authorize(self.caller)?;
        Ok(self.services.audit.require_alive()?)
    }

    /// Admits a mutation: the permission and the router write lease, held until the
    /// returned reservation drops.
    ///
    /// # Errors
    /// [`EntwareError::PermissionDenied`] or a busy lease ([`EntwareError::Workflow`]).
    fn write(&self) -> Result<Reservation, EntwareError> {
        preflight::authorize(self.caller)?;
        Ok(self.services.workflow.reserve(
            self.caller.router,
            self.caller.actor,
            self.caller.role,
        )?)
    }

    /// Runs `command` in `session` and adds its output to the digest.
    ///
    /// # Errors
    /// The command's SSH failure.
    // NOT cancel-safe: dropped while a mutation runs, the router may finish it.
    async fn exec(
        &mut self,
        session: &Session,
        command: &EntwareCommand,
    ) -> Result<Output, EntwareError> {
        let output = session.run(command).await?;
        let (hasher, bytes) = self.digest.get_or_insert_with(|| (Sha256::new(), 0));
        for stream in [output.stdout(), output.stderr()] {
            hasher.update(stream.as_bytes());
            let length = u64::try_from(stream.len()).unwrap_or(u64::MAX);
            *bytes = bytes.saturating_add(length);
        }
        Ok(output)
    }

    /// Audits `outcome` with the output digest and returns it.
    ///
    /// # Errors
    /// `outcome`'s error.
    // NOT cancel-safe: the audit entry may be appended after cancellation.
    async fn finish<T>(mut self, outcome: Result<T, EntwareError>) -> Result<T, EntwareError> {
        if let Some((hasher, bytes)) = self.digest.take() {
            self.facts.output_bytes = Some(bytes);
            self.facts.output_sha256 = Some(hex(&hasher.finalize()));
        }
        self.facts
            .record(self.services, self.caller, outcome.as_ref().err())
            .await;
        outcome
    }
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4_u8, byte & 0x0f] {
            text.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    text
}
