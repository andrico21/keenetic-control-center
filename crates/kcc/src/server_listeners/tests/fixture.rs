//! A supervisor over real kit servers on loopback ports.
//!
//! kcc.toml text, state, Web UI, metrics, the live handler and the reload fan-out are built
//! without `Services::open`, which would read the process's master key.

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;
use std::net::TcpListener;

use arc_swap::ArcSwap;
use kcc_app::{
    api_keys::{create_api_key, expose_created_key},
    audit::AuditLog,
    mcp_settings::{
        Candidate, Effective, EnvOverrides, McpBase, commit,
        document::{McpOverrides, McpSettingsDocument},
    },
    permissions::{Role, load_roles},
    persist::StateStore,
    settings::{Config, McpConfig},
};
use kcc_mcp::KccMcp;
use kcc_telemetry::metrics::{instrumentation::SelfMetrics, service::MetricsExporter};
use kcc_web::admin::TransportReload;
use tempfile::TempDir;
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use super::{
    TestResult,
    services::{handler, web},
};
use crate::{
    server::readiness_check,
    server_error::ServerError,
    server_listeners::{
        ListenerSupervisor,
        build::Shared,
        supervisor::{Hook, Supervisor, Windows},
    },
    server_metrics::Metrics,
};

/// The Web password of `alice`.
pub(super) const PASSWORD: &str = "correct horse battery staple";

/// A free loopback port, a moment ago.
pub(super) fn free_port() -> TestResult<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

/// What a fixture starts with.
#[derive(Default)]
pub(super) struct Setup {
    /// Extra `[mcp]` lines.
    pub(super) mcp: String,
    /// Extra kcc.toml text after `[mcp]` (for `[mcp.dedicated]` and the like).
    pub(super) tail: String,
    /// Extra `[server]` lines.
    pub(super) server: String,
    /// Overrides saved on the Web before the start.
    pub(super) saved: Option<McpOverrides>,
    /// The test hook.
    pub(super) hook: Hook,
    /// Shorter windows.
    pub(super) windows: Option<Windows>,
    /// The metrics address, when the test must know it before the start.
    pub(super) metrics: Option<SocketAddr>,
}

/// A running supervisor and what the tests reach it with.
pub(super) struct Fixture {
    /// The state directory.
    pub(super) state: StateStore,
    /// kcc.toml's `[mcp]`.
    base: McpBase,
    /// The administrator role.
    admin: Role,
    /// An admin API key.
    pub(super) key: String,
    /// The queue of changes.
    pub(super) supervisor: ListenerSupervisor,
    /// The handler new sessions clone.
    pub(super) live: Arc<ArcSwap<KccMcp>>,
    /// The reload fan-out.
    pub(super) reload: Arc<TransportReload>,
    /// What the generations are built from.
    pub(super) shared: Arc<Shared>,
    /// The metrics address.
    pub(super) metrics: SocketAddr,
    /// Fires the termination.
    pub(super) terminate: CancellationToken,
    /// The supervisor task.
    pub(super) serving: JoinHandle<Result<(), ServerError>>,
    /// The first main generation's address, as the state watcher gets it.
    pub(super) first: oneshot::Receiver<SocketAddr>,
    /// Keeps the files.
    _directory: TempDir,
}

impl Fixture {
    /// Starts a supervisor as `setup` says, with `toolsets = ["core", "raw"]`,
    /// `allow_destructive = true`, Web UI and metrics, and `server.shutdown_timeout = 1 s`.
    pub(super) async fn start(setup: Setup) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let metrics = match setup.metrics {
            Some(address) => address,
            None => SocketAddr::from(([127, 0, 0, 1], free_port()?)),
        };
        let config = Config::from_toml_str(&format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {}\nshutdown_timeout = \"1s\"\n{}\n\n[web]\nenabled = true\n\n[metrics]\nenabled = true\nbind = \"{metrics}\"\n\n[mcp]\nhttp_enabled = true\ntoolsets = [\"core\", \"raw\"]\nallow_destructive = true\n{}\n{}\n",
            free_port()?,
            setup.server,
            setup.mcp,
            setup.tail
        ))?;
        config.validate()?;
        let roles = load_roles(&state)?;
        let admin = roles
            .iter()
            .find(|role| role.name == "admin")
            .cloned()
            .ok_or("no admin role")?;
        let created = create_api_key(
            &state,
            &admin,
            "probe".to_owned(),
            "admin".to_owned(),
            0,
            None,
        )?;
        let base = McpBase::new(&config, &EnvOverrides::default());
        if let Some(saved) = &setup.saved {
            commit(
                &state,
                &base.plan_update(&state, &admin, saved, &|_name| Some(false))?,
            )?;
        }
        let effective = base.effective(&state)?;
        let audit = AuditLog::spawn(&state)?;
        let (handler, poller) = handler(&state, (&effective, &audit), (&roles, &admin)).await?;
        let reload = Arc::new(TransportReload::new(
            state.clone(),
            handler.tool_specs().to_vec(),
        ));
        let live = Arc::new(ArcSwap::from_pointee(handler));
        let web = web(&state, &config, &audit, (roles, &admin))?;
        let exporter = Arc::new(MetricsExporter::new(
            poller,
            &config.metrics,
            SelfMetrics::new("test")?,
        )?);
        let shared = Arc::new(Shared {
            readiness: readiness_check(state.dir().to_owned(), audit),
            state: state.clone(),
            web: Some(web),
            metrics: Some(Metrics::new(exporter, metrics)),
            live: Arc::clone(&live),
            reload: Arc::clone(&reload),
            config,
        });
        let (supervisor, queue, status) = ListenerSupervisor::channel();
        let (ready, first) = oneshot::channel();
        let started = Box::pin(
            Supervisor::new(Arc::clone(&shared), effective, status)
                .with(setup.windows.unwrap_or_default(), setup.hook)
                .start(ready),
        )
        .await?;
        let terminate = CancellationToken::new();
        let fired = terminate.clone();
        let serving = tokio::spawn(started.serve(queue, async move { fired.cancelled().await }));
        Ok(Self {
            state,
            base,
            admin,
            key: expose_created_key(&created).to_owned(),
            supervisor,
            live,
            reload,
            shared,
            metrics,
            terminate,
            serving,
            first,
            _directory: directory,
        })
    }

    /// The candidate setting what `change` sets, planned on the current settings.
    pub(super) fn plan(&self, change: &McpOverrides) -> TestResult<Candidate> {
        self.plan_on(&self.state, change)
    }

    /// The candidate setting what `change` sets, planned on `state`'s settings.
    pub(super) fn plan_on(
        &self,
        state: &StateStore,
        change: &McpOverrides,
    ) -> TestResult<Candidate> {
        Ok(self
            .base
            .plan_update(state, &self.admin, change, &|_name| Some(false))?)
    }

    /// The main listener's address.
    pub(super) fn main(&self) -> TestResult<SocketAddr> {
        Ok(self
            .supervisor
            .status()
            .main
            .ok_or("no main listener")?
            .address)
    }

    /// The dedicated listener's address.
    pub(super) fn dedicated(&self) -> TestResult<SocketAddr> {
        Ok(self
            .supervisor
            .status()
            .dedicated
            .ok_or("no dedicated listener")?
            .address)
    }

    /// `mcp_settings.json`'s revision (0 when absent).
    pub(super) fn revision(&self) -> TestResult<u64> {
        Ok(self
            .state
            .read::<McpSettingsDocument>()?
            .unwrap_or_default()
            .revision)
    }

    /// The effective settings with their sources, as `mcp_settings.json` gives them now.
    pub(super) fn effective(&self) -> TestResult<Effective> {
        Ok(self.base.effective(&self.state)?)
    }

    /// The effective settings `mcp_settings.json` gives now.
    pub(super) fn saved(&self) -> TestResult<McpConfig> {
        Ok(self.base.effective(&self.state)?.into_settings())
    }

    /// Fires the termination and waits until the supervisor returned.
    pub(super) async fn stop(self) -> TestResult<Result<(), ServerError>> {
        self.terminate.cancel();
        Ok(self.serving.await?)
    }
}
