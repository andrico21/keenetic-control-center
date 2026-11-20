//! The preset action over two fake routers through the real run path, in real time: the
//! preset is captured from `office` and applied to `home`.

mod apply;
mod armed;
mod recover;
mod refuse;

extern crate alloc;

use alloc::sync::Arc;
use core::{net::SocketAddr, pin::Pin, time::Duration};

use kcc_app::{
    accounts::{Clock, SystemClock},
    audit::{Actor, ActorKind, AuditEntry, read_entries},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    role_source::RoleSource,
    schedules::{ledger::Trigger, store::SchedulesDocument},
    settings::{CliConfig, OutboundConfig},
    workflow::{Reservation, WorkflowError},
};
use kcc_config::config_text::{flatten, parse};
use kcc_migrate::{
    apply::{Clock as ApplyClock, SystemClock as ApplySystemClock},
    presets::model::{CaptureRequest, PresetSource, PresetSourceKind},
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, migration, model::Profile,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::{sync::watch, time::timeout};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::server_schedules::{
    RunDeps, Timings,
    actions::{ActionDeps, Actions, tests::deps},
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

/// The preset's id.
const PRESET: &str = "night";

/// The router the preset is captured from.
const OFFICE: &str = "office";

/// The first DNS upstream the preset carries.
const FIRST: &str = "dns-proxy tls upstream 1.1.1.1 853";

/// The second DNS upstream the preset carries.
const SECOND: &str = "dns-proxy tls upstream 9.9.9.9 853";

/// The id of the preset schedule.
const ID: &str = "0000000000000e01";

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// A run-now by alice.
fn now() -> Trigger {
    Trigger::Now {
        requested_by: "web:alice".to_owned(),
    }
}

/// The configured lines of configuration `text`.
fn lines(text: &str) -> TestResult<Vec<String>> {
    Ok(flatten(&parse(text)?)
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// An apply clock that moves only when the test advances it, and records every wait.
#[derive(Debug, Default)]
struct HandClock {
    /// Time on this clock.
    now: watch::Sender<Duration>,
    /// Every wait asked for, in order.
    waits: watch::Sender<Vec<Duration>>,
}

impl HandClock {
    /// Moves the clock forward by `by`.
    fn advance(&self, by: Duration) {
        self.now.send_modify(|now| *now = now.saturating_add(by));
    }

    /// Waits until someone waits on the clock for longer than `than`, and answers how long.
    async fn waiting_longer(&self, than: Duration) -> TestResult<Duration> {
        let mut waits = self.waits.subscribe();
        let seen = timeout(
            WAIT,
            waits.wait_for(|seen| seen.iter().any(|wait| *wait > than)),
        )
        .await??;
        seen.iter()
            .copied()
            .find(|wait| *wait > than)
            .ok_or_else(|| "no long wait".into())
    }
}

impl ApplyClock for HandClock {
    fn now(&self) -> Duration {
        *self.now.borrow()
    }

    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let until = self.now().saturating_add(duration);
        let mut now = self.now.subscribe();
        self.waits.send_modify(|waits| waits.push(duration));
        Box::pin(async move {
            drop(now.wait_for(|moved| *moved >= until).await);
        })
    }
}

/// How a bench is built.
struct Setup {
    /// The target's model and firmware.
    profile: Profile,
    /// The target's faults.
    faults: FaultInjection,
    /// The preset applier's clock.
    clock: Arc<dyn ApplyClock>,
    /// The router scope of alice's role `ops`, which holds every permission.
    scope: Vec<String>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            profile: Profile::default(),
            faults: FaultInjection::default(),
            clock: Arc::new(ApplySystemClock::default()),
            scope: vec!["*".to_owned()],
        }
    }
}

/// Two fake routers, a state directory and the real actions over them.
struct Bench {
    /// Holds the state directory.
    _directory: TempDir,
    /// The state directory.
    state: StateStore,
    /// `home`, where the preset is applied.
    target: Handle,
    /// `office`, where the preset is captured.
    source: Handle,
    /// The real actions.
    actions: Arc<ActionDeps>,
    /// Lines and claimed jobs.
    recorder: Arc<Recorder>,
    /// The run path over the real actions; alice owns every schedule.
    deps: Arc<RunDeps>,
}

impl Bench {
    /// Serves `home` (router mode) and `office` (default) and builds the run path.
    async fn start(setup: Setup) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let (home, target) = FakeRouter::builder(setup.profile)
            .faults(setup.faults)
            .build()?
            .with_migration(scenario)
            .serve(local)
            .await?;
        let (office, source) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(local)
            .await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        for (id, address) in [(ROUTER, home), (OFFICE, office)] {
            let url = Url::parse(&format!("http://{address}"))?;
            let profile =
                ManagedRouterProfile::new(id.to_owned(), url, "admin".to_owned(), password.clone());
            registry.create(&admin(), profile).await?;
        }
        let recorder = Arc::new(Recorder::default());
        let notices: Arc<dyn Notices> = Arc::<Recorder>::clone(&recorder);
        let actions =
            Arc::new(deps::actions((&state, registry), Arc::clone(&notices), setup.clock).await?);
        let known = Arc::new(Accounts::default());
        known.set("alice", Lookup::Role("ops".to_owned()));
        let accounts: Arc<dyn AccountLookup> = known;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let run: Arc<dyn Actions> = Arc::<ActionDeps>::clone(&actions);
        let ops = Role::new("ops".to_owned(), Permission::ALL, setup.scope);
        let deps = Arc::new(RunDeps {
            state: state.clone(),
            accounts,
            roles: RoleSource::new(vec![admin(), ops]),
            cli: CliConfig::default(),
            audit: actions.audit().clone(),
            clock,
            notices: Some(notices),
            actions: run,
            timings: Timings::default(),
            stop: CancellationToken::new(),
        });
        Ok(Self {
            _directory: directory,
            state,
            target,
            source,
            actions,
            recorder,
            deps,
        })
    }

    /// Puts `added` into `office`'s running configuration and captures its `group`
    /// settings as the preset.
    async fn capture_office(&self, group: &str, added: &[&str]) -> TestResult {
        let client = self.actions.registry().client(OFFICE).await?;
        for line in added {
            drop(client.parse(line).await?);
        }
        self.capture(group, &self.source.running_config_text())
    }

    /// Captures the `group` settings of configuration `text` as the preset, from `office`.
    fn capture(&self, group: &str, text: &str) -> TestResult {
        let source = PresetSource::new(
            PresetSourceKind::Router,
            Some(OFFICE.to_owned()),
            "Keenetic".to_owned(),
            "4.3.0".to_owned(),
            1_800_000_000,
        );
        let request = CaptureRequest::new(
            PRESET.to_owned(),
            "Night".to_owned(),
            String::new(),
            vec![group.to_owned()],
            source,
            "tester".to_owned(),
        );
        drop(
            self.actions
                .presets()
                .capture(&admin(), &parse(text)?, request)?,
        );
        Ok(())
    }

    /// Stores the preset schedule [`ID`] on `home`, owned by alice.
    fn schedule(&self, ack_documentation_tier: bool) -> TestResult {
        let action = json!({
            "kind": "preset",
            "preset_id": PRESET,
            "ack_documentation_tier": ack_documentation_tier,
        });
        let mut document = SchedulesDocument::default();
        document.schedules = vec![schedule(ID, (&["mon"], 3, 0, "UTC"), &action, 0)?];
        self.state.write(&document)?;
        Ok(())
    }

    /// Runs the preset schedule now.
    async fn run(&self) -> TestResult<Report> {
        Ok(timeout(WAIT, run_once(&self.deps, ID, now())).await?)
    }

    /// Takes `home`'s lease as an operator would.
    fn reserve(&self) -> Result<Reservation, WorkflowError> {
        let operator = Actor::new(ActorKind::Cli, "cli:operator".to_owned());
        self.actions.workflow().reserve(ROUTER, &operator, &admin())
    }

    /// Every parser line `home` received.
    fn commands(&self) -> Vec<String> {
        self.target
            .request_log()
            .iter()
            .flat_map(|record| {
                record
                    .commands()
                    .flatten()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The `schedule.run` audit entries written so far.
    async fn run_entries(&self) -> TestResult<Vec<AuditEntry>> {
        let _queued: usize = self.actions.audit().flush(WAIT).await;
        Ok(read_entries(self.state.dir())?
            .into_iter()
            .filter(|entry| entry.action == "schedule.run")
            .collect())
    }
}
