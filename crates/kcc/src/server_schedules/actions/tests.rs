//! The actions over a fake router through the real run path, in real time with short
//! waits.

mod policy;
mod restart;

extern crate alloc;

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};

use kcc_app::{
    accounts::{Clock, SystemClock},
    audit::{Actor, ActorKind, AuditEntry, AuditLog, read_entries},
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    role_source::RoleSource,
    schedules::{ledger::Trigger, model::Schedule, store::SchedulesDocument},
    secrets::MasterKey,
    settings::{CliConfig, OutboundConfig},
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{RouterCtx, clients};
use kcc_migrate::{apply::SystemClock as ApplyClock, presets::store::PresetStore};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use serde_json::json;
use tempfile::TempDir;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::ActionDeps;
use crate::server_schedules::{
    RunDeps, Timings,
    notices::Notices,
    owner::{AccountLookup, Lookup},
    run::{Report, run_once},
    tests::{
        rig::{ROUTER, TestResult, schedule},
        stub::{Accounts, Recorder},
    },
};

/// Upper bound of every wait.
const WAIT: Duration = Duration::from_secs(60);

/// A registered client the setup puts on the router.
const PHONE: &str = "02:00:00:00:13:01";

/// A client the fixture lists as not registered.
const VISITOR: &str = "02:00:00:00:10:02";

/// A run-now request.
fn now() -> Trigger {
    Trigger::Now {
        requested_by: "web:alice".to_owned(),
    }
}

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// A fake router, a state directory and the real actions over them.
struct Bench {
    /// Holds the state directory.
    _directory: TempDir,
    /// The state directory.
    state: StateStore,
    /// The fake router, while it serves.
    router: Option<Handle>,
    /// Router profiles.
    registry: Arc<RouterRegistry>,
    /// The change workflow.
    workflow: Arc<ChangeWorkflow>,
    /// Background jobs.
    jobs: Arc<JobRunner>,
    /// Backups.
    backups: Arc<BackupStore>,
    /// The audit writer.
    audit: AuditLog,
    /// Lines, mutes and claimed jobs.
    recorder: Arc<Recorder>,
    /// The run path over the real actions.
    deps: Arc<RunDeps>,
}

impl Bench {
    /// Serves the default KN-1811 fake and builds the run path with `timings`.
    async fn start(timings: Timings, schedules: Vec<Schedule>) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut document = SchedulesDocument::default();
        document.schedules = schedules;
        state.write(&document)?;
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let (address, router) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        registry
            .create(
                &admin(),
                ManagedRouterProfile::new(
                    ROUTER.to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password,
                ),
            )
            .await?;
        let key = MasterKey::from_bytes([9_u8; 32]);
        let audit = AuditLog::spawn(&state)?;
        let backups = Arc::new(BackupStore::new(state.clone(), key.duplicate()));
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone()).await?;
        let recorder = Arc::new(Recorder::default());
        let notices: Arc<dyn Notices> = Arc::<Recorder>::clone(&recorder);
        let actions = ActionDeps {
            registry: Arc::clone(&registry),
            workflow: Arc::clone(&workflow),
            jobs: Arc::clone(&jobs),
            backups: Arc::clone(&backups),
            audit: audit.clone(),
            presets: Arc::new(PresetStore::new(state.clone(), key)),
            notify: Some(Arc::clone(&notices)),
            apply_clock: Arc::new(ApplyClock::default()),
            timings,
        };
        let known = Arc::new(Accounts::default());
        known.set("alice", Lookup::Role("admin".to_owned()));
        let accounts: Arc<dyn AccountLookup> = known;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let deps = Arc::new(RunDeps {
            state: state.clone(),
            accounts,
            roles: RoleSource::new(vec![admin()]),
            cli: CliConfig::default(),
            audit: audit.clone(),
            clock,
            notices: Some(notices),
            actions: Arc::new(actions),
            timings,
            stop: CancellationToken::new(),
        });
        Ok(Self {
            _directory: directory,
            state,
            router: Some(router),
            registry,
            workflow,
            jobs,
            backups,
            audit,
            recorder,
            deps,
        })
    }

    /// The serving fake router.
    fn fake(&self) -> TestResult<&Handle> {
        self.router
            .as_ref()
            .ok_or_else(|| "the router stopped".into())
    }

    /// Registers [`PHONE`] on the router through the change workflow, unsaved.
    async fn register_phone(&self) -> TestResult {
        let setup = Actor::new(ActorKind::Cli, "cli:setup".to_owned());
        let mut changes = self.workflow.begin(ROUTER, setup, &admin(), false).await?;
        let info = self.registry.poll_info(ROUTER).await?;
        let router = RouterCtx::new(changes.client(), Catalog::for_router(&info)?);
        let operation = clients::plan_register(&router, PHONE.parse()?, "phone")?;
        drop(clients::apply(&mut changes, &router, &operation).await?);
        Ok(())
    }

    /// Runs schedule `id` for `trigger`.
    async fn run(&self, id: &str, trigger: Trigger) -> TestResult<Report> {
        Ok(timeout(WAIT, run_once(&self.deps, id, trigger)).await?)
    }

    /// The `schedule.run` audit entries written so far.
    async fn run_entries(&self) -> TestResult<Vec<AuditEntry>> {
        let _queued: usize = self.audit.flush(WAIT).await;
        Ok(read_entries(self.state.dir())?
            .into_iter()
            .filter(|entry| entry.action == "schedule.run")
            .collect())
    }

    /// Every parser line the router received.
    fn commands(&self) -> TestResult<Vec<String>> {
        Ok(self
            .fake()?
            .request_log()
            .iter()
            .flat_map(|record| {
                record
                    .commands()
                    .flatten()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect())
    }
}

/// A policy switch of `mac` to `policy`.
fn switch(id: &str, mac: &str, policy: &str) -> TestResult<Schedule> {
    schedule(
        id,
        (&["mon"], 3, 0, "UTC"),
        &json!({"kind": "policy_switch", "mac": mac, "policy": policy}),
        0,
    )
}
