//! A session with the `entware-ssh` toolset: the fake router `lab-1`, the fake Entware SSH
//! server enrolled for it by a Web administrator, and the SSH services attached to the
//! handler.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of the step that failed"
)]

use alloc::{collections::BTreeSet, sync::Arc};
use core::net::SocketAddr;

use kcc_app::{
    accounts::{Clock, SystemClock},
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    jobs::JobRunner,
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    role_source::RoleSource,
    secrets::MasterKey,
    settings::{OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    entware::ssh::{
        Caller, SshServices,
        enrol::{self, Confirmation},
        ops::{
            job::{self, Mutation, Request},
            names,
        },
    },
};
use kcc_mcp::KccMcp;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
    entware_ssh::{self, FakeEntwareSsh},
    model::Profile,
};
use rmcp::{
    ServiceError, ServiceExt as _,
    model::{CallToolRequestParams, Tool},
    service::{RoleClient, RunningService},
};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::duplex;
use url::Url;

use crate::support::{ROUTER, Reply, Setup, TestResult, admin};

/// The router, the enrolled SSH fake and one connected session.
pub(crate) struct Rig {
    /// Temporary state.
    _directory: TempDir,
    /// The fake router.
    router: Handle,
    /// The fake Entware SSH server.
    ssh: entware_ssh::Handle,
    /// The client session.
    client: RunningService<RoleClient, ()>,
    /// The handler the session was opened on.
    server: KccMcp,
    /// The server's job runner.
    jobs: Arc<JobRunner>,
    /// The live roles the handler authorizes against.
    roles: RoleSource,
    /// The SSH services attached to the handler.
    services: Arc<SshServices>,
    /// The registry reaching the router.
    registry: Arc<RouterRegistry>,
}

/// A registry reaching the served router, the router's address and its handle.
type Served = (RouterRegistry, SocketAddr, Handle);

/// Serves `fake` on a Unix socket the returned registry dials for its address.
#[cfg(unix)]
fn serve(registry: RouterRegistry, fake: FakeRouter) -> TestResult<Served> {
    let (address, socket, handle) = fake.serve_local()?;
    Ok((registry.with_local_socket(address, socket), address, handle))
}

/// Serves `fake` on loopback TCP; `registry` reaches it as it is.
// cancel-safe: dropped, the router stops with its handle.
#[cfg(not(unix))]
async fn serve(registry: RouterRegistry, fake: FakeRouter) -> TestResult<Served> {
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    Ok((registry, address, handle))
}

/// Points the router's SSH port at the fake and enrols it as a Web administrator.
// NOT cancel-safe: a dropped enrolment leaves the record pending.
async fn enrol_router(services: &SshServices, registry: &RouterRegistry, port: u16) -> TestResult {
    let (actor, role) = (Actor::new(ActorKind::Web, "alice".to_owned()), admin());
    let caller = Caller::new(ROUTER, &actor, &role);
    drop(enrol::set_port(services, &caller, port).await?);
    let catalog = Catalog::for_router(&registry.poll_info(ROUTER).await?)?;
    let ctx = RouterCtx::new(registry.client(ROUTER).await?, catalog);
    let ticket = enrol::probe(services, &ctx, &caller).await?;
    let confirmation = Confirmation::new(
        ticket.nonce.clone(),
        ticket.fingerprint.clone(),
        SecretString::from(entware_ssh::DEFAULT_PASSWORD),
    );
    drop(enrol::bootstrap(services, &ctx, &caller, confirmation).await?);
    Ok(())
}

impl Rig {
    /// Starts both fakes, enrols the router and opens a session on `setup`.
    // NOT cancel-safe: a dropped start leaves the enrolment pending.
    pub(crate) async fn start(setup: Setup) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let unreached = RouterRegistry::new(state.clone(), &[], &outbound)?;
        let fake = FakeRouter::builder(Profile::default()).build()?;
        #[cfg(unix)]
        let (reached, address, router) = serve(unreached, fake)?;
        #[cfg(not(unix))]
        let (reached, address, router) = serve(unreached, fake).await?;
        let registry = Arc::new(reached);
        let password =
            kcc_testkit::write_secret_file(directory.path(), "lab-password", DEFAULT_PASSWORD)?;
        let profile = ManagedRouterProfile::new(
            ROUTER.to_owned(),
            Url::parse(&format!("http://{address}"))?,
            DEFAULT_LOGIN.to_owned(),
            password,
        );
        registry.create(&admin(), profile).await?;
        let key = MasterKey::from_bytes([5_u8; 32]);
        let backups = Arc::new(BackupStore::new(state.clone(), key.duplicate()));
        let audit = AuditLog::spawn(&state)?;
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let services = Arc::new(SshServices::new(
            Arc::clone(&workflow),
            Arc::clone(&registry),
            audit.clone(),
            &key,
            clock,
        ));
        let (ssh_address, ssh) = FakeEntwareSsh::spawn(setup.ssh).await?;
        enrol_router(&services, &registry, ssh_address.port()).await?;
        let jobs = JobRunner::open(state, Arc::clone(&registry), audit.clone()).await?;
        let roles = RoleSource::new(vec![admin(), setup.role.clone()]);
        let live = roles.clone();
        let reaching = Arc::clone(&registry);
        let server = KccMcp::new(
            setup.mcp,
            PrivacyConfig::default(),
            Arc::clone(&registry),
            workflow,
            Arc::clone(&jobs),
            Poller::new(registry),
            vec![admin()],
            setup.role,
        )
        .with_role_source(roles)
        .with_audit(audit)
        .with_entware_ssh(Arc::clone(&services), setup.limit);
        let session = server.clone();
        let (server_io, client_io) = duplex(1 << 20);
        drop(tokio::spawn(async move {
            if let Ok(running) = session.serve(server_io).await {
                drop(running.waiting().await);
            }
        }));
        let client = ().serve(client_io).await?;
        Ok(Self {
            _directory: directory,
            router,
            ssh,
            client,
            server,
            jobs,
            roles: live,
            services,
            registry: reaching,
        })
    }

    /// Starts an install of `package` as an administrator's write job on the handler's
    /// job runner, as the package tool does, and returns the job id.
    // NOT cancel-safe: the job may start without its id reaching the caller.
    pub(crate) async fn start_install(&self, package: &str) -> TestResult<String> {
        let catalog = Catalog::for_router(&self.registry.poll_info(ROUTER).await?)?;
        let ctx = RouterCtx::new(self.registry.client(ROUTER).await?, catalog);
        let actor = Actor::new(ActorKind::Mcp, "alice".to_owned());
        let request = Request::new(ctx, ROUTER.to_owned(), actor, admin());
        let mutation = Mutation::Install(names::package(package)?);
        Ok(job::start(&self.jobs, Arc::clone(&self.services), request, mutation).await?)
    }

    /// The job `id` once it ended, as `kcc_job_status` reads it.
    pub(crate) async fn ended(&self, id: &str) -> TestResult<Value> {
        self.jobs.ended(id).await;
        let status = self.call("kcc_job_status", json!({ "id": id })).await?;
        Ok(status.ok()?.clone())
    }

    /// The live roles: a replacement binds the session's next call.
    pub(crate) const fn roles(&self) -> &RoleSource {
        &self.roles
    }

    /// The fake router.
    pub(crate) const fn router(&self) -> &Handle {
        &self.router
    }

    /// The fake Entware SSH server.
    pub(crate) const fn ssh(&self) -> &entware_ssh::Handle {
        &self.ssh
    }

    /// The handler the session was opened on.
    pub(crate) const fn server(&self) -> &KccMcp {
        &self.server
    }

    /// Names of the tools the session lists.
    pub(crate) async fn tool_names(&self) -> TestResult<BTreeSet<String>> {
        Ok(self
            .client
            .list_all_tools()
            .await?
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect())
    }

    /// The tool `name` as the session lists it.
    pub(crate) async fn listed(&self, name: &str) -> TestResult<Tool> {
        Ok(self
            .client
            .list_all_tools()
            .await?
            .into_iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| format!("no tool {name}"))?)
    }

    /// Calls `tool` with `arguments`.
    pub(crate) async fn call(&self, tool: &str, arguments: Value) -> TestResult<Reply> {
        let Value::Object(object) = arguments else {
            return Err("arguments must be an object".into());
        };
        let params = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
        let result = self.client.call_tool(params).await?;
        let text = result
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|content| content.text.clone())
            .ok_or("tool returned no text")?;
        Ok(Reply::new(
            result.is_error == Some(true),
            serde_json::from_str(&text)?,
        ))
    }

    /// Whether the session refuses `tool` as unknown, the refusal of a tool the gates do
    /// not admit.
    pub(crate) async fn unknown(&self, tool: &str, arguments: Value) -> TestResult<bool> {
        let Value::Object(object) = arguments else {
            return Err("arguments must be an object".into());
        };
        let request = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
        match self.client.call_tool(request).await {
            Err(ServiceError::McpError(error)) => Ok(error.message == "tool not found"),
            Err(other) => Err(other.into()),
            Ok(_result) => Ok(false),
        }
    }

    /// Router requests, SSH connections and SSH commands so far.
    pub(crate) fn contacts(&self) -> (u64, u64, u64) {
        let counters = self.ssh.counters();
        (
            self.router.request_count(),
            counters.connections,
            counters.commands,
        )
    }

    /// Fails unless `call` (tool and arguments) is refused with `code` while neither the
    /// router nor the SSH server is contacted.
    pub(crate) async fn refused_quietly(&self, call: (&str, Value), code: &str) -> TestResult {
        let (tool, arguments) = call;
        let before = self.contacts();
        let reply = self.call(tool, arguments.clone()).await?;
        if reply.error() != Some(code) {
            return Err(format!("{tool} {arguments}: expected {code}, got {reply:?}").into());
        }
        let after = self.contacts();
        if after != before {
            return Err(format!("{tool} {arguments}: contacts {before:?} -> {after:?}").into());
        }
        Ok(())
    }

    /// Waits for the job a mutation answered with to end, then reads it with
    /// `kcc_job_status`.
    pub(crate) async fn finished(&self, started: &Reply) -> TestResult<Value> {
        let id = started
            .ok()?
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no job id: {started:?}"))?
            .to_owned();
        self.jobs.ended(&id).await;
        let status = self.call("kcc_job_status", json!({ "id": id })).await?;
        Ok(status.ok()?.clone())
    }

    /// Ends the session and stops both fakes.
    pub(crate) async fn stop(self) -> TestResult {
        drop(self.client.cancel().await?);
        drop(self.server);
        drop(self.jobs);
        self.router.shutdown().await?;
        self.ssh.shutdown().await?;
        Ok(())
    }
}
