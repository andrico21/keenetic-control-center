//! Enrolment harness: the fake router, the fake Entware SSH server and the SSH services.

use alloc::sync::Arc;
use core::{
    hash::BuildHasher as _,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::hash::RandomState;

use kcc_app::{
    accounts::{Clock, SystemClock},
    audit::{Actor, ActorKind, AuditEntry, verify_chain},
    entware_ssh::state::{SshEnrolment, SshStore},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use kcc_domain::{
    RouterCtx,
    entware::ssh::{
        Caller, SshServices,
        enrol::{self, Confirmation, Enrolled, ProbeTicket},
        error::EntwareError,
    },
};
use kcc_ssh::transport::Timeouts;
use kcc_testkit::{
    entware_ssh::{Config, Counters, DEFAULT_PASSWORD, FakeEntwareSsh, Handle},
    model::Firmware,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tokio::time::timeout;

use crate::support::{Fixture, TestResult, administrator};

/// Upper bound of every awaited flow: generous, the timings are real time.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The router id of the fixture profile.
pub(crate) const ROUTER: &str = "router";

/// A wall clock a test can move forward.
#[derive(Debug)]
pub(crate) struct HandClock(AtomicU64);

impl Clock for HandClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl HandClock {
    /// Moves the clock `seconds` ahead.
    pub(crate) fn advance(&self, seconds: u64) {
        let _previous = self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

/// A random lowercase hex marker, built at run time.
pub(crate) fn marker() -> String {
    format!(
        "{:016x}{:016x}",
        RandomState::new().hash_one(1_u8),
        RandomState::new().hash_one(2_u8)
    )
}

/// The confirmation of `ticket` with `password`.
pub(crate) fn confirm(ticket: &ProbeTicket, password: &str) -> Confirmation {
    Confirmation::new(
        ticket.nonce.clone(),
        ticket.fingerprint.clone(),
        SecretString::from(password),
    )
}

/// The audit parameter `key` of `entry`, `null` when absent.
pub(crate) fn param(entry: &AuditEntry, key: &str) -> Value {
    entry
        .params_redacted
        .get(key)
        .cloned()
        .unwrap_or(Value::Null)
}

/// A web actor named `name`.
pub(crate) fn actor(name: &str) -> Actor {
    Actor::new(ActorKind::Web, name.to_owned())
}

/// A role with every permission but `Destructive`.
pub(crate) fn operator() -> Role {
    Role::new(
        "operator".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Destructive),
        vec!["*".to_owned()],
    )
}

/// The fake router, the fake Entware SSH server and the services under test.
pub(crate) struct Harness {
    /// Fake router, registry, workflow and audit.
    fixture: Fixture,
    /// The SSH fake's address and handle; `None` once it was shut down.
    ssh: Option<(SocketAddr, Handle)>,
    /// The services under test.
    services: SshServices,
    /// The services' clock.
    clock: Arc<HandClock>,
    /// The master key sealing the SSH state.
    key: MasterKey,
    /// The administrator role.
    admin: Role,
    /// The default actor.
    alice: Actor,
}

impl Harness {
    /// Starts both fakes on `firmware`, the SSH fake with `config`, and points the
    /// router's SSH port at the fake.
    // cancel-safe: dropped, the fakes stop with their handles.
    pub(crate) async fn start(firmware: Firmware, config: Config) -> TestResult<Self> {
        let fixture = Fixture::spawn(firmware).await?;
        let (address, handle) = FakeEntwareSsh::spawn(config).await?;
        let clock = Arc::new(HandClock(AtomicU64::new(
            SystemClock::default().unix_seconds(),
        )));
        let key = MasterKey::from_bytes([9_u8; 32]);
        let mut timeouts = Timeouts::default();
        timeouts.connect = Duration::from_secs(5);
        timeouts.auth = Duration::from_secs(5);
        timeouts.read = Duration::from_secs(10);
        timeouts.mutation = Duration::from_secs(10);
        let shared: Arc<dyn Clock> = Arc::<HandClock>::clone(&clock);
        let services = SshServices::new(
            Arc::clone(fixture.workflow()),
            fixture.registry(),
            fixture.audit().clone(),
            &key,
            shared,
        )
        .with_timeouts(timeouts);
        let harness = Self {
            fixture,
            ssh: Some((address, handle)),
            services,
            clock,
            key,
            admin: administrator(),
            alice: actor("alice"),
        };
        drop(harness.set_port(address.port()).await?);
        Ok(harness)
    }

    /// Starts on 5.1 with the default SSH fake (password `keenetic`, empty userland).
    // cancel-safe: dropped, the fakes stop with their handles.
    pub(crate) async fn default_start() -> TestResult<Self> {
        Self::start(Firmware::V5_1, Config::default()).await
    }

    /// The services under test.
    pub(crate) const fn services(&self) -> &SshServices {
        &self.services
    }

    /// The fixture.
    pub(crate) const fn fixture(&self) -> &Fixture {
        &self.fixture
    }

    /// The router context.
    pub(crate) const fn context(&self) -> &RouterCtx {
        self.fixture.context()
    }

    /// The services' clock.
    pub(crate) fn clock(&self) -> &HandClock {
        &self.clock
    }

    /// The administrator role.
    pub(crate) const fn admin(&self) -> &Role {
        &self.admin
    }

    /// The default actor.
    pub(crate) const fn alice(&self) -> &Actor {
        &self.alice
    }

    /// The administrator calling as `alice`.
    pub(crate) const fn caller(&self) -> Caller<'_> {
        Caller::new(ROUTER, &self.alice, &self.admin)
    }

    /// The SSH fake's handle.
    pub(crate) fn ssh(&self) -> TestResult<&Handle> {
        Ok(&self.ssh.as_ref().ok_or("the SSH fake was shut down")?.1)
    }

    /// The SSH fake's address.
    pub(crate) fn ssh_address(&self) -> TestResult<SocketAddr> {
        Ok(self.ssh.as_ref().ok_or("the SSH fake was shut down")?.0)
    }

    /// The SSH fake's counters.
    pub(crate) fn counters(&self) -> TestResult<Counters> {
        Ok(self.ssh()?.counters())
    }

    /// Stops the SSH fake: its port refuses connections from now on.
    // cancel-safe: dropped, the fake stops with its handle.
    pub(crate) async fn stop_ssh(&mut self) -> TestResult {
        let (_address, handle) = self.ssh.take().ok_or("the SSH fake was shut down")?;
        handle.shutdown().await?;
        Ok(())
    }

    /// An independent view of the sealed SSH state.
    pub(crate) fn store(&self) -> TestResult<SshStore> {
        Ok(SshStore::new(
            StateStore::open(&self.fixture.state_dir())?,
            self.key.duplicate(),
        ))
    }

    /// The router's enrolment record on disk.
    pub(crate) fn record(&self) -> TestResult<Option<SshEnrolment>> {
        Ok(self.store()?.load(ROUTER)?)
    }

    /// The router's private key on disk.
    pub(crate) fn private_key(&self) -> TestResult<Option<String>> {
        Ok(self
            .store()?
            .load_key(ROUTER)?
            .map(|key| key.expose_secret().to_owned()))
    }

    /// The `authorized_keys` lines marked for the router.
    pub(crate) fn kcc_lines(&self) -> TestResult<Vec<String>> {
        Ok(self
            .ssh()?
            .authorized_keys()
            .lines()
            .filter(|line| line.ends_with(" kcc:router"))
            .map(str::to_owned)
            .collect())
    }

    /// The audit entries written so far.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(verify_chain(&self.fixture.state_dir())?)
    }

    /// The audit entries of `action`.
    pub(crate) fn audited(&self, action: &str) -> TestResult<Vec<AuditEntry>> {
        Ok(self
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .collect())
    }

    /// Sets the router's SSH port as the administrator.
    // cancel-safe: local only; the record write is atomic.
    pub(crate) async fn set_port(&self, port: u16) -> Result<SshEnrolment, EntwareError> {
        enrol::set_port(&self.services, &self.caller(), port).await
    }

    /// Probes as `alice`.
    // cancel-safe: dropped, at most a ticket nobody holds remains.
    pub(crate) async fn probe(&self) -> TestResult<ProbeTicket> {
        Ok(timeout(
            LIMIT,
            enrol::probe(&self.services, self.context(), &self.caller()),
        )
        .await??)
    }

    /// Bootstraps as `alice` with `ticket` and `password`.
    // NOT cancel-safe: a dropped bootstrap leaves the enrolment pending.
    pub(crate) async fn bootstrap_with(
        &self,
        ticket: &ProbeTicket,
        password: &str,
    ) -> TestResult<Result<Enrolled, EntwareError>> {
        Ok(timeout(
            LIMIT,
            enrol::bootstrap(
                &self.services,
                self.context(),
                &self.caller(),
                confirm(ticket, password),
            ),
        )
        .await?)
    }

    /// Re-pins as `alice` with `ticket` and `password`.
    // NOT cancel-safe: a dropped re-pin leaves the enrolment pending.
    pub(crate) async fn repin_with(
        &self,
        ticket: &ProbeTicket,
        password: &str,
    ) -> TestResult<Result<Enrolled, EntwareError>> {
        Ok(timeout(
            LIMIT,
            enrol::repin(
                &self.services,
                self.context(),
                &self.caller(),
                confirm(ticket, password),
            ),
        )
        .await?)
    }

    /// Revokes as `alice` through `router`.
    // NOT cancel-safe: a dropped revoke may have removed the line but kept the record.
    pub(crate) async fn revoke_via(
        &self,
        router: &RouterCtx,
    ) -> TestResult<Result<(), EntwareError>> {
        Ok(timeout(LIMIT, enrol::revoke(&self.services, router, &self.caller())).await?)
    }

    /// Probes and bootstraps with Entware's default password; the enrolment must succeed.
    // NOT cancel-safe: a dropped bootstrap leaves the enrolment pending.
    pub(crate) async fn enrol(&self) -> TestResult<Enrolled> {
        let ticket = self.probe().await?;
        Ok(self.bootstrap_with(&ticket, DEFAULT_PASSWORD).await??)
    }
}
