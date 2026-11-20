//! The eligibility check over fake KN-1811 routers in real time: each refusal code and
//! each success, and no write on the router.

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    schedules::model::Action,
    settings::OutboundConfig,
};
use kcc_catalog::Catalog;
use kcc_config::config_text::parse;
use kcc_domain::{RouterCtx, clients};
use kcc_migrate::{
    apply::SystemClock as ApplyClock,
    presets::model::{CaptureRequest, PresetSource, PresetSourceKind},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, migration, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;
use url::Url;

use super::{Draft, ScheduleRefusal, check};
use crate::server_schedules::{
    actions::{ActionDeps, tests::deps},
    notices::Notices,
    preset::PresetRefusal,
    tests::{
        rig::{ROUTER, TestResult},
        stub::Recorder,
    },
};

/// A client the bench registers on `home`.
const PHONE: &str = "02:00:00:00:16:01";

/// A client the fixture lists as not registered.
const VISITOR: &str = "02:00:00:00:10:02";

/// A policy the fake router has.
const POLICY: &str = "Policy0";

/// The router a preset is captured from.
const OFFICE: &str = "office";

/// A router profile whose router stopped.
const GONE: &str = "gone";

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// `action` as stored in `schedules.json`.
fn action(value: &Value) -> TestResult<Action> {
    Ok(serde_json::from_value(value.clone())?)
}

/// A policy switch of `mac` to `policy`.
fn switch(mac: &str, policy: &str) -> TestResult<Action> {
    action(&json!({"kind": "policy_switch", "mac": mac, "policy": policy}))
}

/// `home` (router mode, with migration inventory), `office` (another profile of the same
/// router) and `gone` (a router that stopped), with the real actions.
struct Bench {
    /// Holds the state directory.
    _directory: TempDir,
    /// `home`.
    home: Handle,
    /// The real actions.
    actions: ActionDeps,
}

impl Bench {
    /// Serves the routers and builds the actions.
    async fn start() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let (address, home) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(local)
            .await?;
        let (stopped, gone) = FakeRouter::spawn().await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        for (id, at) in [(ROUTER, address), (OFFICE, address), (GONE, stopped)] {
            let url = Url::parse(&format!("http://{at}"))?;
            let profile =
                ManagedRouterProfile::new(id.to_owned(), url, "admin".to_owned(), password.clone());
            registry.create(&admin(), profile).await?;
        }
        gone.shutdown().await?;
        let notify: Arc<dyn Notices> = Arc::new(Recorder::default());
        let actions =
            deps::actions((&state, registry), notify, Arc::new(ApplyClock::default())).await?;
        Ok(Self {
            _directory: directory,
            home,
            actions,
        })
    }

    /// Registers [`PHONE`] on `home` through the change workflow, unsaved.
    async fn register_phone(&self) -> TestResult {
        let setup = Actor::new(ActorKind::Cli, "cli:setup".to_owned());
        let workflow = self.actions.workflow();
        let mut changes = workflow.begin(ROUTER, setup, &admin(), false).await?;
        let info = self.actions.registry().poll_info(ROUTER).await?;
        let router = RouterCtx::new(changes.client(), Catalog::for_router(&info)?);
        let operation = clients::plan_register(&router, PHONE.parse()?, "phone")?;
        drop(clients::apply(&mut changes, &router, &operation).await?);
        Ok(())
    }

    /// Captures a DNS preset `night` from `office`.
    fn capture_preset(&self) -> TestResult {
        let source = PresetSource::new(
            PresetSourceKind::Router,
            Some(OFFICE.to_owned()),
            "Keenetic".to_owned(),
            "4.3.0".to_owned(),
            1_800_000_000,
        );
        let request = CaptureRequest::new(
            "night".to_owned(),
            "Night".to_owned(),
            String::new(),
            vec!["dns-secure".to_owned()],
            source,
            "tester".to_owned(),
        );
        let text = "dns-proxy tls upstream 1.1.1.1 853\n!\n";
        drop(
            self.actions
                .presets()
                .capture(&admin(), &parse(text)?, request)?,
        );
        Ok(())
    }

    /// Every parser line `home` received.
    fn commands(&self) -> Vec<String> {
        self.home
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

    /// Checks `action` on `router` with `role`.
    async fn check(
        &self,
        role: &Role,
        (router, action): (&str, &Action),
    ) -> Result<Option<String>, ScheduleRefusal> {
        check(&self.actions, role, &Draft::new(router, action)).await
    }
}

/// Todo 16: a policy switch needs a registered client and an existing policy.
///
/// The registered client under an existing policy passes; an unregistered client is
/// `client_unknown`, an unknown policy `policy_unknown`; the check sends no line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_switch_needs_a_registered_client_and_a_known_policy() -> TestResult {
    let bench = Bench::start().await?;
    bench.register_phone().await?;
    let sent = bench.commands();

    let known = bench
        .check(&admin(), (ROUTER, &switch(PHONE, POLICY)?))
        .await;
    let visitor = bench
        .check(&admin(), (ROUTER, &switch(VISITOR, POLICY)?))
        .await;
    let unknown = bench
        .check(&admin(), (ROUTER, &switch(PHONE, "Missing0")?))
        .await;

    assert_eq!(known, Ok(None));
    assert_eq!(
        visitor.map_err(ScheduleRefusal::code),
        Err("client_unknown")
    );
    assert_eq!(
        unknown.map_err(ScheduleRefusal::code),
        Err("policy_unknown")
    );
    assert_eq!(bench.commands(), sent, "the check sends no line");
    Ok(())
}

/// Todo 16: a router that cannot be read refuses a policy switch with `router`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_router_is_refused() -> TestResult {
    let bench = Bench::start().await?;

    let refused = bench.check(&admin(), (GONE, &switch(PHONE, POLICY)?)).await;

    assert_eq!(refused.map_err(ScheduleRefusal::code), Err("router"));
    Ok(())
}

/// Todo 16: a backup and a reboot pass without a router request; a role without
/// `ManageSchedules`, without `Destructive` for a reboot, or outside the router is
/// `forbidden`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permissions_are_checked_before_the_router() -> TestResult {
    let bench = Bench::start().await?;
    let (backup, reboot) = (
        action(&json!({"kind": "backup"}))?,
        action(&json!({"kind": "reboot"}))?,
    );
    let unmanaged = Role::new(
        "operator".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::ManageSchedules),
        vec!["*".to_owned()],
    );
    let gentle = Role::new(
        "gentle".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Destructive),
        vec!["*".to_owned()],
    );
    let elsewhere = Role::new(
        "elsewhere".to_owned(),
        Permission::ALL,
        vec![OFFICE.to_owned()],
    );

    let passed = (
        bench.check(&admin(), (ROUTER, &backup)).await,
        bench.check(&admin(), (ROUTER, &reboot)).await,
        bench.check(&gentle, (ROUTER, &backup)).await,
    );
    let refused = [
        bench.check(&unmanaged, (ROUTER, &backup)).await,
        bench.check(&gentle, (ROUTER, &reboot)).await,
        bench
            .check(&elsewhere, (ROUTER, &switch(PHONE, POLICY)?))
            .await,
    ];

    assert_eq!(passed, (Ok(None), Ok(None), Ok(None)));
    for result in refused {
        assert_eq!(result.map_err(ScheduleRefusal::code), Err("forbidden"));
    }
    assert_eq!(bench.home.request_count(), 0, "no router request");
    Ok(())
}

/// Todo 16: a preset schedule answers the preset's source router, or the preset's
/// refusal code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preset_answers_its_source_router_or_its_refusal() -> TestResult {
    let bench = Bench::start().await?;
    let night = action(&json!({
        "kind": "preset",
        "preset_id": "night",
        "ack_documentation_tier": false,
    }))?;

    let missing = bench.check(&admin(), (ROUTER, &night)).await;
    bench.capture_preset()?;
    let ready = bench.check(&admin(), (ROUTER, &night)).await;

    assert_eq!(
        missing.clone(),
        Err(ScheduleRefusal::Preset(PresetRefusal::Unavailable))
    );
    assert_eq!(
        missing.map_err(ScheduleRefusal::code),
        Err("preset_unavailable")
    );
    assert_eq!(ready, Ok(Some(OFFICE.to_owned())));
    assert_eq!(bench.commands(), Vec::<String>::new(), "nothing is sent");
    Ok(())
}
