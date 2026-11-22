//! Shared domain integration fixture.
#![expect(
    dead_code,
    clippy::definition_in_module_root,
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::std_instead_of_alloc,
    reason = "each integration crate compiles this shared fixture independently and uses only its required lifecycle seams"
)]

use core::{error::Error, net::SocketAddr, str::FromStr as _};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::{ChangeSet, ChangeWorkflow},
};
use kcc_catalog::Catalog;
use kcc_domain::{DomainError, RouterCtx};
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, migration,
    model::{Firmware, Model, Profile},
    outbound::connect_manager,
    time::{Clock, MockClock},
};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;
use tracing::{Level, subscriber::DefaultGuard};
use url::Url;

/// The fake-router profiles every domain suite runs on: KN-1811 on 4.3.9 and on 5.1.
pub(crate) const PROFILES: [Firmware; 2] = [Firmware::V4_3, Firmware::V5_1];

/// A toggleable service that `firmware`'s catalog documents: `service iperf3` is new in
/// 5.1, so the 4.3.9 profile toggles `service udpxy`.
pub(crate) const fn toggle_service(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::V4_3 => "udpxy",
        Firmware::V5_0 | Firmware::V5_1 | _ => "iperf3",
    }
}

/// Whether `outcome` is the planner's typed catalog refusal, produced before any request.
pub(crate) const fn refused_by_catalog<T>(outcome: &kcc_domain::Result<T>) -> bool {
    matches!(outcome, Err(DomainError::Validation { issues }) if !issues.is_empty())
}

/// Integration-test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// TRACE-level byte capture retained for secret-boundary assertions.
pub(crate) struct TraceCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
    _guard: DefaultGuard,
}

impl TraceCapture {
    /// Installs an in-memory subscriber for the current test scope.
    pub(crate) fn install() -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = TraceWriter(Arc::clone(&bytes));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        Self {
            bytes,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Returns captured UTF-8 output after flushing each tracing event.
    pub(crate) fn text(&self) -> TestResult<String> {
        let bytes = self
            .bytes
            .lock()
            .map_err(|_error| "trace capture poisoned")?
            .clone();
        Ok(String::from_utf8(bytes)?)
    }
}

/// Cloneable writer used by the tracing formatter.
#[derive(Clone)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_error| io::Error::other("trace capture poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One running fake router and protected workflow.
pub(crate) struct Fixture {
    /// Temporary state root.
    directory: TempDir,
    /// Fake-router observation handle.
    handle: Handle,
    /// Typed domain context.
    context: RouterCtx,
    /// Protected workflow service.
    workflow: Arc<ChangeWorkflow>,
    /// Router registry shared by workflow and jobs.
    registry: Arc<RouterRegistry>,
    /// Injected fake-router clock for deterministic reboot windows.
    clock: Option<Arc<MockClock>>,
    /// The workflow's audit writer.
    audit: AuditLog,
    /// Loopback address the fake router listens on.
    address: SocketAddr,
    /// The Unix socket the registry dials for `address`, when the fake serves one.
    socket: Option<PathBuf>,
}

impl Fixture {
    /// Starts KN-1811 on `firmware`.
    pub(crate) async fn spawn(firmware: Firmware) -> TestResult<Self> {
        Self::spawn_with(firmware, None, FaultInjection::default()).await
    }

    /// Starts KN-1811 on `firmware` with selected fake-router faults.
    pub(crate) async fn spawn_with_faults(
        firmware: Firmware,
        faults: FaultInjection,
    ) -> TestResult<Self> {
        Self::spawn_with(firmware, None, faults).await
    }

    /// Starts `model` on its 5.1 seed firmware.
    pub(crate) async fn spawn_model(model: Model) -> TestResult<Self> {
        Self::spawn_builder(FakeRouter::builder(Profile::latest(model)), None).await
    }

    /// Starts KN-1811 with focused replacements for embedded show fixtures.
    pub(crate) async fn spawn_with_show<I, S>(firmware: Firmware, fixtures: I) -> TestResult<Self>
    where
        I: IntoIterator<Item = (S, Value)>,
        S: Into<String>,
    {
        let builder = fixtures.into_iter().fold(
            FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?),
            |builder, (path, value)| builder.show_fixture(path, value),
        );
        Self::spawn_builder(builder, None).await
    }

    /// Starts KN-1811 on `firmware` reporting system mode `mode`, with selected faults.
    pub(crate) async fn spawn_mode(
        firmware: Firmware,
        mode: &str,
        faults: FaultInjection,
    ) -> TestResult<Self> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let router = FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?)
            .faults(faults)
            .reached_directly()
            .build()?
            .with_migration(scenario);
        Self::spawn_router(router, None).await
    }

    /// Starts KN-1811 on `firmware` with a deterministic clock.
    pub(crate) async fn spawn_clocked(firmware: Firmware) -> TestResult<Self> {
        Self::spawn_with(
            firmware,
            Some(Arc::new(MockClock::new())),
            FaultInjection::default(),
        )
        .await
    }

    /// Starts KN-1811 on `firmware` with a deterministic clock and selected faults.
    pub(crate) async fn spawn_clocked_with_faults(
        firmware: Firmware,
        faults: FaultInjection,
    ) -> TestResult<Self> {
        Self::spawn_with(firmware, Some(Arc::new(MockClock::new())), faults).await
    }

    /// Starts the fixture with an optional injected fake-router clock.
    async fn spawn_with(
        firmware: Firmware,
        clock: Option<Arc<MockClock>>,
        faults: FaultInjection,
    ) -> TestResult<Self> {
        let base_builder =
            FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?).faults(faults);
        let configured_builder = match &clock {
            Some(source) => {
                let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(source);
                base_builder.clock(injected)
            }
            None => base_builder,
        };
        Self::spawn_builder(configured_builder, clock).await
    }

    /// Starts one configured fake-router builder and connects the domain context.
    async fn spawn_builder(
        builder: kcc_testkit::FakeRouterBuilder,
        clock: Option<Arc<MockClock>>,
    ) -> TestResult<Self> {
        Self::spawn_router(builder.reached_directly().build()?, clock).await
    }

    /// Starts KN-1811 on `firmware` for a test under a paused tokio clock: on Unix it answers
    /// on a Unix socket, since a paused clock can jump ahead of a loopback TCP reply that is
    /// written but not yet readable.
    pub(crate) async fn spawn_local(firmware: Firmware) -> TestResult<Self> {
        Self::spawn_local_builder(FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?)).await
    }

    /// Starts one configured fake-router builder for a test under a paused tokio clock, as
    /// [`Self::spawn_local`] does; on Unix the router registry dials the Unix socket too.
    pub(crate) async fn spawn_local_builder(
        builder: kcc_testkit::FakeRouterBuilder,
    ) -> TestResult<Self> {
        let router = builder.reached_directly().build()?;
        let loopback = OutboundPolicy::default().with_loopback(true);
        #[cfg(unix)]
        let ((address, socket), handle, outbound) = {
            let (address, socket, handle) = router.serve_local()?;
            let outbound = loopback.with_local_socket(address, socket.clone());
            ((address, Some(socket)), handle, outbound)
        };
        #[cfg(not(unix))]
        let ((address, handle), outbound) =
            (router.serve(([127, 0, 0, 1], 0).into()).await?, loopback);
        #[cfg(not(unix))]
        let (address, socket) = (address, None);
        Self::connect((address, socket), handle, None, outbound).await
    }

    /// Serves one built fake router and connects the domain context.
    async fn spawn_router(router: FakeRouter, clock: Option<Arc<MockClock>>) -> TestResult<Self> {
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        Self::connect(
            (address, None),
            handle,
            clock,
            OutboundPolicy::default().with_loopback(true),
        )
        .await
    }

    /// Connects the domain context to the fake router served at `address` through
    /// `outbound`; the registry dials `socket` for `address` when one is given.
    async fn connect(
        (address, socket): (SocketAddr, Option<PathBuf>),
        handle: Handle,
        clock: Option<Arc<MockClock>>,
        outbound: OutboundPolicy,
    ) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let registry =
            Arc::new(registry_for(&state, directory.path(), (address, socket.clone())).await?);
        let origin = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = Arc::new(
            RciClient::connect_with(
                origin.clone(),
                credentials,
                RciClientOptions::default().with_outbound(outbound.clone()),
            )
            .await?,
        );
        let manager = connect_manager(
            origin.clone(),
            Credentials::new(
                DEFAULT_LOGIN.to_owned(),
                SecretString::from(DEFAULT_PASSWORD.to_owned()),
            ),
            &outbound,
        )
        .await?;
        let info = RouterInfo::detect(&manager, &origin).await?;
        let catalog = Catalog::for_router(&info)?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([26_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow = ChangeWorkflow::new(state, Arc::clone(&registry), backups, audit.clone());
        Ok(Self {
            directory,
            handle,
            context: RouterCtx::new(client, catalog),
            workflow,
            registry,
            clock,
            audit,
            address,
            socket,
        })
    }

    /// A second domain context whose profile URL names `host`.
    ///
    /// The host is never looked up: the client is pinned to the fake router's address.
    pub(crate) fn context_via(&self, host: &str) -> TestResult<RouterCtx> {
        let origin = RouterUrl::from_str(&format!("http://{host}:{}", self.address.port()))?;
        let client = RciClient::connect_resolved(
            origin,
            Credentials::new(
                DEFAULT_LOGIN.to_owned(),
                SecretString::from(DEFAULT_PASSWORD.to_owned()),
            ),
            RciClientOptions::default()
                .with_outbound(OutboundPolicy::default().with_loopback(true)),
            &[self.address],
        )?;
        Ok(RouterCtx::new(
            Arc::new(client),
            self.context.catalog.clone(),
        ))
    }

    /// Begins a protected administrator change set.
    pub(crate) async fn changes(&self) -> TestResult<ChangeSet> {
        self.changes_as(&admin_role()).await
    }

    /// Begins a protected change set for `role`.
    pub(crate) async fn changes_as(&self, role: &Role) -> TestResult<ChangeSet> {
        Ok(self
            .workflow
            .begin(
                "router",
                Actor::new(ActorKind::Cli, "test".to_owned()),
                role,
                false,
            )
            .await?)
    }

    /// Returns the protected workflow service.
    pub(crate) const fn workflow(&self) -> &Arc<ChangeWorkflow> {
        &self.workflow
    }

    /// Returns the workflow's audit writer.
    pub(crate) const fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Returns the typed router context.
    pub(crate) const fn context(&self) -> &RouterCtx {
        &self.context
    }

    /// Returns the fake-router observation handle.
    pub(crate) const fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Returns the isolated state directory for audit-boundary assertions.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }

    /// Returns the router registry shared with job tests.
    pub(crate) fn registry(&self) -> Arc<RouterRegistry> {
        Arc::clone(&self.registry)
    }

    /// Advances the injected fake-router clock.
    pub(crate) fn advance(&self, by: core::time::Duration) -> TestResult {
        let clock = self.clock.as_ref().ok_or("fixture has no mock clock")?;
        clock.advance(by);
        Ok(())
    }

    /// A second workflow on its own state directory for the same router: its lease is
    /// independent of [`Self::workflow`]'s, as another kcc process's would be.
    pub(crate) async fn separate_workflow(&self) -> TestResult<(TempDir, Arc<ChangeWorkflow>)> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let registry = Arc::new(
            registry_for(
                &state,
                directory.path(),
                (self.address, self.socket.clone()),
            )
            .await?,
        );
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([27_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow = ChangeWorkflow::new(state, registry, backups, audit);
        Ok((directory, workflow))
    }

    /// Opens a job runner on the fixture state.
    pub(crate) async fn jobs(&self) -> TestResult<Arc<kcc_app::jobs::JobRunner>> {
        let state = StateStore::open(&self.directory.path().join("state"))?;
        let audit = AuditLog::spawn(&state)?;
        Ok(kcc_app::jobs::JobRunner::open(state, Arc::clone(&self.registry), audit).await?)
    }

    /// Stops the fake router.
    pub(crate) async fn shutdown(self) -> TestResult {
        let Self {
            directory,
            handle,
            context: _,
            workflow: _,
            registry: _,
            clock: _,
            audit: _,
            address: _,
            socket: _,
        } = self;
        handle.shutdown().await?;
        drop(directory);
        Ok(())
    }
}

/// A router registry on `state` holding the profile `router` at `address`, dialing
/// `socket` for it when one is given; the password file is written below `directory`.
async fn registry_for(
    state: &StateStore,
    directory: &std::path::Path,
    (address, socket): (SocketAddr, Option<PathBuf>),
) -> TestResult<RouterRegistry> {
    let password_file = kcc_testkit::write_secret_file(directory, "password", DEFAULT_PASSWORD)?;
    let mut config = OutboundConfig::default();
    config.allow_loopback = true;
    let built = RouterRegistry::new(state.clone(), &[], &config)?;
    #[cfg(unix)]
    let registry = match socket {
        Some(path) => built.with_local_socket(address, path),
        None => built,
    };
    #[cfg(not(unix))]
    let registry = {
        drop(socket);
        built
    };
    registry
        .create(
            &admin_role(),
            ManagedRouterProfile::new(
                "router".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                DEFAULT_LOGIN.to_owned(),
                password_file,
            ),
        )
        .await?;
    Ok(registry)
}

/// Administrator role used by protected workflow tests.
fn admin_role() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// Returns the administrator role for direct authorization tests.
pub(crate) fn administrator() -> Role {
    admin_role()
}
