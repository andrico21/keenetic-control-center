//! A `kcc serve` with JSON TRACE logs over a fake router and a fake Telegram.
//!
//! The router offers a firmware update; notifications are switched on with one chat in
//! the state before the server starts, and the bot token is set later on the Web page.
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
        NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats},
    },
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, fake_telegram::FakeTelegram,
    firmware_update::FirmwareUpdate, model::Profile, toml_text,
};
use reqwest::{Client, header, redirect::Policy};
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

/// The firmware the fake router offers.
pub(crate) const FIRMWARE: &str = "5.1.9";

/// The router's id.
pub(crate) const ROUTER: &str = "fake";

/// Upper bound for starting the server.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound for a message to arrive.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(90);

/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// Whether the log line `line` is the JSON event of a listener that serves.
fn listening(line: &str) -> bool {
    serde_json::from_str::<Value>(line).is_ok_and(|event| {
        event
            .pointer("/fields/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("listening"))
    })
}

/// State, configuration, the fakes and the clients of one server.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// `kcc.toml`.
    config: PathBuf,
    /// `kcc.toml` with [`PORT_HOLE`] for the listen port.
    template: String,
    /// Base URL of the listener, once it serves.
    base: String,
    /// The bot token, built at run time.
    token: String,
    /// The fake Telegram.
    telegram: FakeTelegram,
    /// The fake router.
    _router: Handle,
    /// HTTP client that does not follow redirects.
    http: Client,
}

impl Fixture {
    /// Writes the state (accounts `alice` and `bob`, notifications on for one chat) and
    /// the configuration, and starts the fakes.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let accounts = AccountStore::new(
            state.clone(),
            MasterKey::from_bytes([17_u8; 32]),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        );
        for (name, role) in [("alice", "admin"), ("bob", "operator")] {
            accounts.create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                NewAccount::new(
                    name.to_owned(),
                    SecretString::from(PASSWORD),
                    role.to_owned(),
                ),
            )?;
        }
        let mut settings = NotifySettings::default();
        settings.enabled = true;
        settings.chats = Chats::new(vec![Chat::new(
            ChatId::parse("4242")?,
            ChatLabel::parse("ops")?,
        )])?;
        state.write(&settings)?;
        master_key::write(&directory.path().join("master.key"), [17_u8; 32])?;
        let token = format!(
            "{}:{}",
            7_000_001_u32,
            ["serve", "notify", "secret", "token", "part", "qrstuvwx"].join("_")
        );
        let telegram = FakeTelegram::spawn().await?;
        telegram.expect_token(&token);
        let (address, router) = FakeRouter::builder(Profile::default())
            .build()?
            .with_firmware_update(FirmwareUpdate::Available(FIRMWARE.to_owned()))
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n\n[web]\nenabled = true\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {}\n\n[notify.telegram]\napi_url = \"{}\"\n\n[observability]\nlog_level = \"trace\"\nlog_format = \"json\"\n\n[[routers]]\nname = \"{ROUTER}\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {}\n",
            toml_text::path(state.dir()),
            telegram.url(),
            toml_text::path(&password),
        );
        let config = directory.path().join("kcc.toml");
        let _installed = default_provider().install_default();
        Ok(Self {
            directory,
            config,
            template,
            base: String::new(),
            token,
            telegram,
            _router: router,
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

    /// One sign-in to the Web UI as `user` with a wrong password.
    pub(crate) async fn wrong_sign_in(&self, user: &str) -> TestResult {
        let login = self
            .http
            .get(format!("{}/ui/login", self.base))
            .send()
            .await?;
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_owned)
            .ok_or("missing Set-Cookie")?;
        let html = login.text().await?;
        let csrf = html
            .split_once("<meta name=\"csrf-token\" content=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(token, _)| token.to_owned())
            .ok_or("no CSRF token")?;
        let wrong = format!("{PASSWORD}-wrong");
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("username", user)
            .append_pair("password", &wrong)
            .finish();
        drop(
            self.http
                .post(format!("{}/ui/login", self.base))
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, &self.base)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await?,
        );
        Ok(())
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

    /// The bot token.
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// The state directory.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.directory.path().join("state"))?)
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
