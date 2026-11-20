//! A scheduler over a temporary state directory, a wall clock that moves with tokio's
//! paused clock (plus steps), stub actions and recorded lines; no sockets.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

use kcc_app::{
    accounts::Clock,
    audit::AuditLog,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    role_source::RoleSource,
    schedules::{
        ledger::{RunLedger, RunRecord, RunState},
        model::{Owner, Schedule, ScheduleState},
        store::SchedulesDocument,
    },
    settings::{CliConfig, OutboundConfig},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::stub::{Accounts, Recorder};
use crate::server_schedules::{
    RunDeps, Scheduler, Timings,
    actions::Actions,
    notices::Notices,
    owner::{AccountLookup, Lookup},
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The router every schedule runs on.
pub(crate) const ROUTER: &str = "home";

/// Upper bound of every wait, in virtual time.
pub(crate) const WAIT: Duration = Duration::from_hours(72);

/// A schedule `id` from its JSON parts: `when` as `[days, hour, minute, zone]`.
pub(crate) fn schedule(
    id: &str,
    when: (&[&str], u8, u8, &str),
    action: &Value,
    updated_at: i64,
) -> TestResult<Schedule> {
    let (days, hour, minute, zone) = when;
    Ok(serde_json::from_value(json!({
        "id": id,
        "name": format!("job-{id}"),
        "router": ROUTER,
        "when": {"days": days, "hour": hour, "minute": minute, "zone": zone},
        "action": action,
        "owner": {"kind": "web", "username": "alice"},
        "state": {"state": "active"},
        "created_at": updated_at,
        "updated_at": updated_at,
    }))?)
}

/// A reboot schedule on `router` owned by `owner`, for owner checks.
pub(crate) fn schedule_of(router: &str, owner: Owner) -> TestResult<Schedule> {
    let mut built = schedule(
        "00000000000000aa",
        (&["mon"], 3, 0, "UTC"),
        &json!({"kind": "reboot"}),
        0,
    )?;
    built.router = router.to_owned();
    built.owner = owner;
    Ok(built)
}

/// The wall clock: a base, tokio's elapsed virtual time, and steps.
#[derive(Debug)]
pub(crate) struct WallClock {
    /// Unix seconds at `origin`.
    base: i64,
    /// Virtual instant of `base`.
    origin: Instant,
    /// Sum of the steps, seconds.
    step: AtomicI64,
}

impl WallClock {
    /// Steps the wall clock by `seconds` (negative: back).
    pub(crate) fn step(&self, seconds: i64) {
        let _: i64 = self.step.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Unix seconds now.
    pub(crate) fn now(&self) -> i64 {
        let elapsed = i64::try_from(self.origin.elapsed().as_secs()).unwrap_or(i64::MAX);
        self.base
            .saturating_add(elapsed)
            .saturating_add(self.step.load(Ordering::SeqCst))
    }
}

impl Clock for WallClock {
    fn unix_seconds(&self) -> u64 {
        u64::try_from(self.now()).unwrap_or(0)
    }
}

/// A scheduler and what it runs on.
pub(crate) struct Rig {
    /// Holds the state directory.
    _directory: TempDir,
    /// The state directory.
    state: StateStore,
    /// The wall clock.
    clock: Arc<WallClock>,
    /// The roles in force.
    roles: RoleSource,
    /// Web accounts; `alice` holds `admin`.
    accounts: Arc<Accounts>,
    /// Lines.
    recorder: Arc<Recorder>,
    /// The router registry with [`ROUTER`].
    registry: Arc<RouterRegistry>,
    /// The audit writer.
    audit: AuditLog,
}

impl Rig {
    /// State with `schedules`, the wall clock at `now`, router [`ROUTER`] registered.
    pub(crate) async fn new(schedules: Vec<Schedule>, now: i64) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut document = SchedulesDocument::default();
        document.schedules = schedules;
        state.write(&document)?;
        let password = kcc_testkit::write_secret_file(directory.path(), "router.password", "x")?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        registry
            .create(
                &admin,
                ManagedRouterProfile::new(
                    ROUTER.to_owned(),
                    Url::parse("http://192.0.2.1")?,
                    "admin".to_owned(),
                    password,
                ),
            )
            .await?;
        let accounts = Arc::new(Accounts::default());
        accounts.set("alice", Lookup::Role("admin".to_owned()));
        Ok(Self {
            audit: AuditLog::spawn(&state)?,
            _directory: directory,
            state,
            clock: Arc::new(WallClock {
                base: now,
                origin: Instant::now(),
                step: AtomicI64::new(0),
            }),
            roles: RoleSource::new(vec![admin]),
            accounts,
            recorder: Arc::new(Recorder::default()),
            registry,
        })
    }

    /// The state directory.
    pub(crate) const fn state(&self) -> &StateStore {
        &self.state
    }

    /// The wall clock.
    pub(crate) fn clock(&self) -> &WallClock {
        &self.clock
    }

    /// The roles in force.
    pub(crate) const fn roles(&self) -> &RoleSource {
        &self.roles
    }

    /// Web accounts; `alice` holds `admin`.
    pub(crate) fn accounts(&self) -> &Accounts {
        &self.accounts
    }

    /// Lines.
    pub(crate) fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    /// Starts the scheduler with `actions`.
    pub(crate) fn start(&self, actions: Arc<dyn Actions>) -> Scheduler {
        let accounts: Arc<dyn AccountLookup> = Arc::<Accounts>::clone(&self.accounts);
        let clock: Arc<dyn Clock> = Arc::<WallClock>::clone(&self.clock);
        let notices: Arc<dyn Notices> = Arc::<Recorder>::clone(&self.recorder);
        let deps = RunDeps {
            state: self.state.clone(),
            accounts,
            roles: self.roles.clone(),
            cli: CliConfig::default(),
            audit: self.audit.clone(),
            clock,
            notices: Some(notices),
            actions,
            timings: Timings::default(),
            stop: CancellationToken::new(),
        };
        Scheduler::start(deps, Arc::clone(&self.registry))
    }

    /// The runs of schedule `id`.
    pub(crate) fn runs(&self, id: &str) -> TestResult<Vec<RunRecord>> {
        Ok(RunLedger::new(self.state.clone()).runs(id)?)
    }

    /// The runs of `id` as (slot, state).
    pub(crate) fn states(&self, id: &str) -> TestResult<Vec<(Option<i64>, RunState)>> {
        Ok(self
            .runs(id)?
            .into_iter()
            .map(|run| (run.slot, run.state))
            .collect())
    }

    /// Schedule `id`'s state.
    pub(crate) fn schedule_state(&self, id: &str) -> TestResult<ScheduleState> {
        self.state
            .read::<SchedulesDocument>()?
            .unwrap_or_default()
            .schedules
            .into_iter()
            .find(|found| found.id == id)
            .map(|found| found.state)
            .ok_or_else(|| "schedule is gone".into())
    }
}
