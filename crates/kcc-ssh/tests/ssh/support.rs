//! Shared setup: the fake, admitted addresses, pins, credentials and timeouts.

use core::{error::Error, net::SocketAddr, time::Duration};

use kcc_rci::{OutboundPolicy, RouterUrl};
use kcc_ssh::{
    grammar::RouterId,
    keys::{Auth, HostKeyPin},
    pool::SshPool,
    session::Session,
    transport::{AdmittedAddresses, PinnedTarget, Timeouts},
};
use kcc_testkit::entware_ssh::{Config, DEFAULT_PASSWORD, FakeEntwareSsh, Handle, Service};
use secrecy::SecretString;

/// Result of a test that propagates setup errors.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Upper bound of every test body: generous, since the timings are real time.
pub(crate) const LIMIT: Duration = Duration::from_secs(20);

/// Timeouts long enough for loopback on a slow CI host.
pub(crate) fn timeouts() -> Timeouts {
    let mut timeouts = Timeouts::default();
    timeouts.connect = Duration::from_secs(10);
    timeouts.auth = Duration::from_secs(10);
    timeouts.read = Duration::from_secs(10);
    timeouts.mutation = Duration::from_secs(10);
    timeouts
}

/// The fake with two packages, one upgrade, one installable package and four services.
pub(crate) fn config() -> Config {
    Config::default()
        .installed("entware-opt", "227000-3")
        .installed("opkg", "2024.10.16~38eccbb1-1")
        .upgradable("opkg", "2024.10.16~38eccbb1-2")
        .installable("mc", "4.8.31-1")
        .service("S51dropbear", Service::new("dropbear").running())
        .service("S80nginx", Service::new("nginx"))
        .service("S90broken", Service::new("broken").failing())
        .service("S99off", Service::new("off").disabled())
}

/// A running fake.
pub(crate) struct Fake {
    /// Its loopback address.
    address: SocketAddr,
    /// Its control handle.
    handle: Handle,
}

impl Fake {
    /// Starts a fake with `config`.
    // cancel-safe: dropped before the bind completes, nothing runs.
    pub(crate) async fn spawn(config: Config) -> TestResult<Self> {
        let (address, handle) = FakeEntwareSsh::spawn(config).await?;
        Ok(Self { address, handle })
    }

    /// Its loopback address.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Its control handle.
    pub(crate) const fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The pin of the fake's current host key.
    pub(crate) fn pin(&self) -> TestResult<HostKeyPin> {
        Ok(HostKeyPin::from_openssh(
            &self.handle.host_key().to_openssh()?,
        )?)
    }

    /// The fake's addresses pinned to its current host key.
    // cancel-safe: dropped, nothing is dialled.
    pub(crate) async fn target(&self) -> TestResult<PinnedTarget> {
        Ok(PinnedTarget::new(
            admitted(self.address).await?,
            self.pin()?,
        ))
    }

    /// A password session through `pool` with `timeouts`.
    // cancel-safe: dropped, the connection is closed; no command was sent.
    pub(crate) async fn session(&self, pool: &SshPool, timeouts: Timeouts) -> TestResult<Session> {
        let target = self.target().await?;
        let router = router()?;
        let slot = pool.acquire(&router).await?;
        Ok(slot.connect(target, password(), timeouts).await?)
    }
}

/// The router id every test uses.
pub(crate) fn router() -> TestResult<RouterId> {
    Ok(RouterId::parse("home")?)
}

/// The fake's loopback address, admitted by a policy that admits loopback.
// cancel-safe: dropped, it abandons a lookup of a literal address.
pub(crate) async fn admitted(address: SocketAddr) -> TestResult<AdmittedAddresses> {
    let router = format!("http://{}", address.ip()).parse::<RouterUrl>()?;
    let policy = OutboundPolicy::default().with_loopback(true);
    Ok(AdmittedAddresses::admit(&policy, &router, address.port()).await?)
}

/// Entware's default password.
pub(crate) fn password() -> Auth {
    Auth::Password(SecretString::from(DEFAULT_PASSWORD))
}
