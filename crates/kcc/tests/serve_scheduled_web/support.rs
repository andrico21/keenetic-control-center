//! A `kcc serve` with the Web UI over a fake router and a fake Telegram.
//!
//! The state holds the administrator `alice`, the operator `bob` and `carol`, whose role
//! `keeper` may read and write every router and manage schedules but not restart one;
//! notifications, scheduled successes included, are on for one chat with the bot token
//! sealed.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, time::Duration};
use std::{env, fs, path::PathBuf, process::Stdio};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    notify_store::{
        NotifyEvent, NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats},
        token::NotifySecrets,
    },
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    schedules::{
        ledger::{RunLedger, RunRecord},
        model::Schedule,
        store::SchedulesDocument,
    },
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, fake_telegram::FakeTelegram, model::Profile, toml_text,
};
use reqwest::{Client, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use serde_json::Value;
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

/// Password of every account.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// The router's id.
pub(crate) const ROUTER: &str = "fake";

/// A client the fake router's fixture lists as registered.
pub(crate) const CLIENT: &str = "02:00:00:00:10:01";

/// Upper bound for starting the server and for one HTTP request.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound for a message to arrive.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(90);

/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// The master key's bytes: account passwords and the bot token are sealed with it.
const KEY: [u8; 32] = [29_u8; 32];

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// Whether the log line `line` is the JSON event of a listener that serves.
fn listening(line: &str) -> bool {
    serde_json::from_str::<Value>(line).is_ok_and(|event| {
        event
            .pointer("/fields/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("listening"))
    })
}

/// State, configuration, the fakes and the HTTP client of one server.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// `kcc.toml`.
    config: PathBuf,
    /// `kcc.toml` with [`PORT_HOLE`] for the listen port.
    template: String,
    /// Base URL of the listener, once it serves.
    base: String,
    /// The state directory.
    state: StateStore,
    /// The fake Telegram.
    telegram: FakeTelegram,
    /// The fake router.
    router: Handle,
    /// HTTP client that does not follow redirects.
    http: Client,
}

impl Fixture {
    /// Writes the state and the configuration and starts the fakes.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        accounts(&state)?;
        let mut settings = NotifySettings::default();
        settings.enabled = true;
        let _: bool = settings.events.insert(NotifyEvent::ScheduledSuccess);
        settings.chats = Chats::new(vec![Chat::new(
            ChatId::parse("4242")?,
            ChatLabel::parse("home")?,
        )])?;
        state.write(&settings)?;
        master_key::write(&directory.path().join("master.key"), KEY)?;
        let token = format!(
            "{}:{}",
            7_000_015_u32,
            ["serve", "scheduled", "web", "token", "part"].join("_")
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
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n\n[web]\nenabled = true\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {}\n\n[notify.telegram]\napi_url = \"{}\"\n\n[observability]\nlog_level = \"info\"\nlog_format = \"json\"\n\n[[routers]]\nname = \"{ROUTER}\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {}\n",
            toml_text::path(state.dir()),
            telegram.url(),
            toml_text::path(&password),
        );
        let _installed = default_provider().install_default();
        Ok(Self {
            config: directory.path().join("kcc.toml"),
            directory,
            template,
            base: String::new(),
            state,
            telegram,
            router,
            http: Client::builder()
                .redirect(Policy::none())
                .timeout(START_TIMEOUT)
                .build()?,
        })
    }

    /// Starts `kcc serve` on a free port and waits until it listens.
    pub(crate) fn serve(&mut self) -> TestResult<Server> {
        let home = self.directory.path().to_owned();
        let ([port], server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            fs::write(
                &self.config,
                self.template.replace(PORT_HOLE, &port.to_string()),
            )?;
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
            let started = await_ready(&lines, listening, START_TIMEOUT)?;
            Ok(match started {
                Start::Ready(seen) => Start::Ready(Server::new(child, lines, seen)),
                Start::AddressInUse => Start::AddressInUse,
            })
        })?;
        self.base = format!("http://127.0.0.1:{port}");
        Ok(server)
    }

    /// The schedules as stored.
    pub(crate) fn schedules(&self) -> TestResult<Vec<Schedule>> {
        Ok(self
            .state
            .read::<SchedulesDocument>()?
            .unwrap_or_default()
            .schedules)
    }

    /// The stored schedule named `name`.
    pub(crate) fn schedule(&self, name: &str) -> TestResult<Schedule> {
        self.schedules()?
            .into_iter()
            .find(|schedule| schedule.name.as_str() == name)
            .ok_or_else(|| format!("no schedule {name:?}").into())
    }

    /// `schedules.json` as JSON, to compare before and after a refused change.
    pub(crate) fn schedules_json(&self) -> TestResult<Value> {
        Ok(serde_json::to_value(
            self.state.read::<SchedulesDocument>()?.unwrap_or_default(),
        )?)
    }

    /// The runs of schedule `id`.
    pub(crate) fn runs(&self, id: &str) -> TestResult<Vec<RunRecord>> {
        Ok(RunLedger::new(self.state.clone()).runs(id)?)
    }

    /// Waits at most 90 s for a message whose text contains `needle`, and returns it.
    pub(crate) async fn message(&self, needle: &str) -> TestResult<String> {
        timeout(MESSAGE_TIMEOUT, async {
            loop {
                let requests = self.telegram.requests();
                if let Some(found) = requests
                    .iter()
                    .find(|request| request.text().contains(needle))
                {
                    return found.text().to_owned();
                }
                self.telegram
                    .wait_for_requests(requests.len().saturating_add(1))
                    .await;
            }
        })
        .await
        .map_err(|_elapsed| format!("no message with {needle:?} within 90 s").into())
    }

    /// The fake router.
    pub(crate) const fn router(&self) -> &Handle {
        &self.router
    }

    /// The HTTP client.
    pub(crate) const fn http(&self) -> &Client {
        &self.http
    }

    /// The listener's base URL; empty until [`Self::serve`] started it.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }
}

/// Creates the accounts `alice` (admin), `bob` (operator) and `carol` (`keeper`).
fn accounts(state: &StateStore) -> TestResult {
    state.update(|roles: &mut RolesDocument| {
        roles.roles.push(Role::new(
            "keeper".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::ManageSchedules,
            ],
            vec!["*".to_owned()],
        ));
    })?;
    let accounts = AccountStore::new(
        state.clone(),
        MasterKey::from_bytes(KEY),
        Duration::from_mins(15),
        Arc::new(SystemClock::default()),
    );
    for (name, role) in [("alice", "admin"), ("bob", "operator"), ("carol", "keeper")] {
        accounts.create(
            &admin(),
            NewAccount::new(
                name.to_owned(),
                SecretString::from(PASSWORD),
                role.to_owned(),
            ),
        )?;
    }
    Ok(())
}
