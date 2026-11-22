//! The guided Entware setup job against the fake router, under a paused tokio clock: the
//! fake's clock follows tokio time, so reboot windows and installer polls take no real time.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

#[path = "entware_setup/commit.rs"]
mod commit;
#[path = "entware_setup/install.rs"]
mod install;
#[path = "entware_setup/refusals.rs"]
mod refusals;
mod support;

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::{JobEvent, JobProgress, JobRecord, JobRunner},
    permissions::Role,
    workflow::ChangeSet,
};
use kcc_domain::entware::setup::{self, SetupError, SetupRequest};
use kcc_testkit::{
    FakeRouter, FakeRouterBuilder, FaultInjection, Handle,
    model::{Firmware, Model, Profile},
    time::Clock,
};
use serde_json::{Value, json};
use tokio::{
    sync::broadcast::Receiver,
    time::{Instant, timeout},
};

use crate::support::{Fixture, TestResult};

/// The closed installer table of the plan, independent of the code under test.
const AARCH64_URL: &str =
    "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz";
/// The little-endian MIPS installer.
const MIPSEL_URL: &str = "https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz";
/// The big-endian MIPS installer.
const MIPS_URL: &str = "https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz";

/// The KN-1811 fixture drive.
const DRIVE: &str = "fixture-media:/";

/// The longest a test waits for a job, in tokio time: past every limit of the job.
const JOB_LIMIT: Duration = Duration::from_hours(2);

/// The fake router's clock: tokio time, paused in these tests.
#[derive(Debug)]
struct TokioClock(Instant);

impl Clock for TokioClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// A fake `model` on 5.1 whose clock is tokio time.
fn router(model: Model) -> FakeRouterBuilder {
    on_profile(Profile::latest(model))
}

/// A fake router of `profile` whose clock is tokio time.
fn on_profile(profile: Profile) -> FakeRouterBuilder {
    let clock: Arc<dyn Clock> = Arc::new(TokioClock(Instant::now()));
    FakeRouter::builder(profile).clock(clock)
}

/// A KN-1811 5.1 `show version` reporting `arch` and the installed `components`.
fn kn1811_version(arch: &str, components: &str) -> Value {
    json!({
        "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
        "model": "Keenetic Ultra", "device": "Ultra", "hw_id": "KN-1811",
        "hw_version": "10000000", "hw_type": "router", "sandbox": "stable",
        "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.", "series": "KN",
        "region": "EA", "arch": arch,
        "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
        "ndw": {"components": components, "features": "wifi2ghz"}
    })
}

/// A KN-1811 on 5.1 with `components` installed (`ndw.components`).
fn kn1811_with(components: &str) -> FakeRouterBuilder {
    router(Model::Kn1811).show_fixture("version", kn1811_version("aarch64", components))
}

/// A KN-1811 on 5.1 that already has `opkg` and `ext`, with `faults`.
fn ready(faults: FaultInjection) -> FakeRouterBuilder {
    kn1811_with("base,usb,storage,opkg,ext").faults(faults)
}

/// A setup of the fixture drive with the automatic installer, confirmed.
fn on_drive() -> SetupRequest {
    SetupRequest::new(setup::DriveChoice::Media(DRIVE.to_owned()), None, true)
}

/// One started fixture with its job runner and event feed.
struct Lab {
    /// The fixture.
    fixture: Fixture,
    /// The job runner.
    jobs: Arc<JobRunner>,
    /// Every job event since the runner opened.
    events: Receiver<JobEvent>,
}

impl Lab {
    /// Serves `builder` and opens a job runner.
    async fn spawn(builder: FakeRouterBuilder) -> TestResult<Self> {
        let fixture = Fixture::spawn_local_builder(builder).await?;
        let jobs = fixture.jobs().await?;
        let events = jobs.subscribe();
        Ok(Self {
            fixture,
            jobs,
            events,
        })
    }

    /// The fake router.
    const fn handle(&self) -> &Handle {
        self.fixture.handle()
    }

    /// Starts the setup `request` as `role` with `changes`.
    async fn start_with(
        &self,
        role: &Role,
        changes: ChangeSet,
        request: SetupRequest,
    ) -> Result<String, SetupError> {
        setup::start(
            &self.jobs,
            self.fixture.registry(),
            Arc::clone(self.fixture.workflow()),
            "router".to_owned(),
            Actor::new(ActorKind::Cli, "test".to_owned()),
            role,
            changes,
            &self.fixture.context().catalog,
            request,
        )
        .await
    }

    /// Starts the setup `request` as the administrator.
    async fn start(&self, request: SetupRequest) -> TestResult<String> {
        let role = support::administrator();
        let changes = self.fixture.changes_as(&role).await?;
        Ok(self.start_with(&role, changes, request).await?)
    }

    /// Waits until job `id` ended and returns its final record.
    async fn finished(&self, id: &str) -> TestResult<JobRecord> {
        timeout(JOB_LIMIT, self.jobs.ended(id)).await?;
        Ok(self.jobs.get(id)?)
    }

    /// Waits for the first event of job `id` that `wanted` accepts.
    async fn reached(
        &mut self,
        id: &str,
        wanted: impl Fn(&JobEvent) -> bool + Send + Sync,
    ) -> TestResult {
        timeout(JOB_LIMIT, async {
            loop {
                let event = self.events.recv().await?;
                if event.id == id && wanted(&event) {
                    return TestResult::Ok(());
                }
            }
        })
        .await?
    }

    /// The structured progress of job `id` received so far, in order.
    fn progress(&mut self, id: &str) -> Vec<Value> {
        let mut seen = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            if let (true, Some(JobProgress::Structured(value))) = (event.id == id, event.detail) {
                seen.push(value);
            }
        }
        seen
    }

    /// Every parser line the router received after the first `mark` requests.
    fn lines_since(&self, mark: usize) -> Vec<String> {
        self.handle()
            .request_log()
            .iter()
            .skip(mark)
            .flat_map(|record| {
                record
                    .commands()
                    .flatten()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The `show log` reads the router received after the first `mark` requests.
    fn log_reads_since(&self, mark: usize) -> usize {
        self.handle()
            .request_log()
            .iter()
            .skip(mark)
            .filter(|record| record.method().as_str() == "POST" && record.path() == "/rci/show/log")
            .count()
    }
}

/// The `step` of a setup progress payload.
fn step(value: &Value) -> Option<&str> {
    value.get("step").and_then(Value::as_str)
}

/// Whether `event` is setup progress in `wanted` with `installer_step`.
fn at_step(event: &JobEvent, wanted: &str, installer_step: Option<u64>) -> bool {
    match &event.detail {
        Some(JobProgress::Structured(value)) => {
            step(value) == Some(wanted)
                && value.get("installer_step").and_then(Value::as_u64) == installer_step
        }
        Some(_) | None => false,
    }
}
