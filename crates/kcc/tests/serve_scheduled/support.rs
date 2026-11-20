//! A `kcc serve` with JSON logs over a fake router and a fake Telegram, with schedules
//! and run records written through the stores before it starts.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use core::{error::Error, net::SocketAddr, time::Duration};
use std::{env, fs, path::PathBuf, process::Stdio};

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    notify_store::{
        NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats},
        token::NotifySecrets,
    },
    permissions::{Permission, Role},
    persist::StateStore,
    schedules::{
        ledger::{RunLedger, RunState, Trigger},
        model::{
            Action, NewSchedule, Owner, ScheduleState,
            names::{ClientMac, PolicyName, ScheduleName},
        },
        store::{ScheduleStore, SchedulesDocument},
        time::{DaySet, WeeklyTime, ZoneName},
    },
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, fake_telegram::FakeTelegram, model::Profile, toml_text,
};
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::time::timeout;

use crate::{
    master_key,
    process::Server,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The router's id.
pub(crate) const ROUTER: &str = "fake";

/// The client the schedule switches.
const PHONE: &str = "02:00:00:00:13:01";

/// Upper bound for starting the server.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound for a message to arrive.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(90);

/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// Where the configuration template takes the router section.
const ROUTERS_HOLE: &str = "{routers}";

/// The master key's bytes.
const KEY: [u8; 32] = [23_u8; 32];

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// The wall clock, Unix seconds.
pub(crate) fn now() -> TestResult<i64> {
    Ok(i64::try_from(SystemClock::default().unix_seconds())?)
}

/// State, configuration and the fakes of one server.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// `kcc.toml`.
    config: PathBuf,
    /// `kcc.toml` with the port and router holes.
    template: String,
    /// The `[[routers]]` section of the fake router.
    routers: String,
    /// The fake Telegram.
    telegram: FakeTelegram,
    /// The fake router.
    router: Handle,
    /// The state directory.
    state: StateStore,
}

impl Fixture {
    /// Writes the state (notifications on for one chat, the bot token sealed) and starts
    /// the fakes.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut settings = NotifySettings::default();
        settings.enabled = true;
        settings.chats = Chats::new(vec![Chat::new(
            ChatId::parse("4242")?,
            ChatLabel::parse("ops")?,
        )])?;
        state.write(&settings)?;
        master_key::write(&directory.path().join("master.key"), KEY)?;
        let token = format!(
            "{}:{}",
            7_000_013_u32,
            ["serve", "scheduled", "secret", "token", "part"].join("_")
        );
        NotifySecrets::set_token(
            &state,
            &MasterKey::from_bytes(KEY),
            &SecretString::from(token.clone()),
        )?;
        let telegram = FakeTelegram::spawn().await?;
        telegram.expect_token(&token);
        let (address, router) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let routers = format!(
            "[[routers]]\nname = \"{ROUTER}\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {}\n",
            toml_text::path(&password),
        );
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {}\n\n[notify.telegram]\napi_url = \"{}\"\n\n[observability]\nlog_level = \"info\"\nlog_format = \"json\"\n\n{ROUTERS_HOLE}",
            toml_text::path(state.dir()),
            telegram.url(),
        );
        Ok(Self {
            config: directory.path().join("kcc.toml"),
            directory,
            template,
            routers,
            telegram,
            router,
            state,
        })
    }

    /// Creates a weekly policy switch on `router`, owned by the CLI principal and last
    /// changed at `at`; returns its id.
    pub(crate) fn schedule(&self, router: &str, at: i64) -> TestResult<String> {
        let days = DaySet::from_names(["mon"])?;
        let new = NewSchedule::new(
            ScheduleName::parse("phone night")?,
            router.to_owned(),
            WeeklyTime::new(days, 3, 0, ZoneName::parse("UTC")?)?,
            Action::PolicySwitch {
                mac: ClientMac::parse(PHONE)?,
                policy: PolicyName::parse("Policy0")?,
            },
        );
        let owner = Owner::Cli {
            os_user: "tester".to_owned(),
        };
        Ok(ScheduleStore::new(self.state.clone())
            .create(&admin(), new, owner, at)?
            .id)
    }

    /// Records a run of slot `slot` of schedule `id` as started at `slot`, as a server
    /// that stopped mid-run leaves it.
    pub(crate) fn started(&self, id: &str, slot: i64) -> TestResult {
        let _started: i64 =
            RunLedger::new(self.state.clone()).begin(id, Trigger::Slot(slot), slot)?;
        Ok(())
    }

    /// The run states of schedule `id`.
    pub(crate) fn runs(&self, id: &str) -> TestResult<Vec<RunState>> {
        Ok(RunLedger::new(self.state.clone())
            .runs(id)?
            .into_iter()
            .map(|run| run.state)
            .collect())
    }

    /// Schedule `id`'s state.
    pub(crate) fn schedule_state(&self, id: &str) -> TestResult<ScheduleState> {
        self.state
            .read::<SchedulesDocument>()?
            .unwrap_or_default()
            .schedules
            .into_iter()
            .find(|schedule| schedule.id == id)
            .map(|schedule| schedule.state)
            .ok_or_else(|| "the schedule is gone".into())
    }

    /// Every parser line the router received.
    pub(crate) fn router_commands(&self) -> Vec<String> {
        self.router
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

    /// The texts of the messages delivered so far.
    pub(crate) fn messages(&self) -> Vec<String> {
        self.telegram
            .requests()
            .iter()
            .map(|request| request.text().to_owned())
            .collect()
    }

    /// Waits at most 90 s until `count` messages arrived.
    pub(crate) async fn await_messages(&self, count: usize) -> TestResult {
        timeout(MESSAGE_TIMEOUT, self.telegram.wait_for_requests(count))
            .await
            .map_err(|_elapsed| format!("fewer than {count} messages within 90 s").into())
    }

    /// Rewrites `kcc.toml` for `port`, with the router when `with_router`.
    pub(crate) fn write_config(&self, port: u16, with_router: bool) -> TestResult {
        let routers = if with_router {
            self.routers.as_str()
        } else {
            ""
        };
        fs::write(
            &self.config,
            self.template
                .replace(PORT_HOLE, &port.to_string())
                .replace(ROUTERS_HOLE, routers),
        )?;
        Ok(())
    }

    /// Starts `kcc serve` on a free port and waits until it listens.
    pub(crate) fn serve(&self) -> TestResult<Server> {
        let home = self.directory.path().to_owned();
        let (_port, server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            self.write_config(port, true)?;
            let mut child = spawning::spawn(
                spawning::command(env!("CARGO_BIN_EXE_kcc"))
                    .args(["serve", "--config", self.config.to_str().ok_or("path")?])
                    .env_clear()
                    // Windows sockets fail to load their provider without SystemRoot.
                    .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
                    .env("PATH", env::var_os("PATH").unwrap_or_default())
                    .env("HOME", &home)
                    .env("XDG_CONFIG_HOME", home.join("config"))
                    .env("XDG_STATE_HOME", home.join("state-home"))
                    .env("LOCALAPPDATA", home.join("state-home"))
                    .env("APPDATA", home.join("config"))
                    .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
                    .env("LANG", "C")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            )?;
            let lines = stderr_lines(&mut child)?;
            let started = await_ready(&lines, |line| line.contains("listening"), START_TIMEOUT)?;
            Ok(match started {
                Start::Ready(seen) => Start::Ready(Server::new(child, lines, (seen, port))),
                Start::AddressInUse => {
                    drop(child.kill());
                    drop(child.wait());
                    Start::AddressInUse
                }
            })
        })?;
        Ok(server)
    }
}
