//! A `kcc serve` process over one fake router, and clients for its Web UI and MCP.
//!
//! The state holds an administrator `alice`, a custom role `ops` (Read, Write,
//! `ManageUsers`) held by the account `olga`, and the API key `ops-key`.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
#[cfg(unix)]
use std::time::Instant;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::{OnceLock, mpsc},
    time::SystemTime,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle};
use reqwest::{Client, Response, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

#[cfg(unix)]
use crate::signal::{self, Signal};
use crate::{
    master_key,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Password of every account.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// Upper bound for every wait on the child process.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// The `ops` role with `permissions` on every router.
pub(crate) fn ops(permissions: &[Permission]) -> Role {
    Role::new(
        "ops".to_owned(),
        permissions.iter().copied(),
        vec!["*".to_owned()],
    )
}

/// The running server; killed on drop.
pub(crate) struct Server {
    /// The `kcc serve` process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// Waits until a stderr line contains `needle`.
    #[cfg(unix)]
    pub(crate) fn wait_for(&self, needle: &str) -> TestResult {
        let deadline = Instant::now()
            .checked_add(PROCESS_TIMEOUT)
            .ok_or("deadline overflow")?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(remaining)
                .map_err(|error| format!("{error} while waiting for {needle:?}"))?;
            if line.contains(needle) {
                return Ok(());
            }
        }
    }

    /// Sends SIGHUP and waits until the reload is applied.
    #[cfg(unix)]
    pub(crate) fn hangup(&self) -> TestResult {
        signal::send(&self.child, Signal::Hangup)?;
        self.wait_for("configuration reloaded from SIGHUP")
    }
}

/// State, configuration and the fake router of one server.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// `kcc.toml`.
    config: PathBuf,
    /// `kcc.toml` with [`PORT_HOLE`] for the listen port.
    template: String,
    /// Base URL of the listener, once it serves.
    base_url: OnceLock<String>,
    /// The plaintext `ops-key`.
    key: String,
    /// The fake router.
    _router: Handle,
}

impl Fixture {
    /// Writes the state and configuration; MCP serves the `core` and `vpn` toolsets.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let (address, router) = FakeRouter::spawn().await?;
        let password_file =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        state.update(|roles: &mut RolesDocument| {
            roles.roles.push(ops(&[
                Permission::Read,
                Permission::Write,
                Permission::Destructive,
                Permission::ManageUsers,
            ]));
        })?;
        let accounts = AccountStore::new(
            state.clone(),
            MasterKey::from_bytes([17_u8; 32]),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        );
        for (name, role) in [("alice", "admin"), ("olga", "ops")] {
            accounts.create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                NewAccount::new(
                    name.to_owned(),
                    SecretString::from(PASSWORD),
                    role.to_owned(),
                ),
            )?;
        }
        let created = create_api_key(
            &state,
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            "ops-key".to_owned(),
            "ops".to_owned(),
            1,
        )?;
        master_key::write(&directory.path().join("master.key"), [17_u8; 32])?;
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\ntoolsets = [\"core\", \"vpn\"]\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"router\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
            state.dir().display().to_string(),
            password_file.display().to_string()
        );
        Ok(Self {
            key: expose_created_key(&created).to_owned(),
            config: directory.path().join("kcc.toml"),
            directory,
            template,
            base_url: OnceLock::new(),
            _router: router,
        })
    }

    /// Starts `kcc serve` on a free port and waits until it listens.
    pub(crate) fn serve(&self) -> TestResult<Server> {
        let home = self.directory.path();
        let ([port], server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            fs::write(
                &self.config,
                self.template.replace(PORT_HOLE, &port.to_string()),
            )?;
            let mut child = spawning::spawn(
                spawning::command(env!("CARGO_BIN_EXE_kcc"))
                    .args(["serve", "--config", self.config.to_str().ok_or("path")?])
                    .env("HOME", home)
                    .env("XDG_CONFIG_HOME", home.join("config"))
                    .env("XDG_STATE_HOME", home.join("state-home"))
                    .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            )?;
            let lines = stderr_lines(&mut child)?;
            let server = Server { child, lines };
            let started = await_ready(
                &server.lines,
                |line| line.contains("listening"),
                PROCESS_TIMEOUT,
            )?;
            Ok(match started {
                Start::Ready(_seen) => Start::Ready(server),
                Start::AddressInUse => Start::AddressInUse,
            })
        })?;
        self.base_url
            .set(format!("http://127.0.0.1:{port}"))
            .map_err(|_served| "the fixture serves once")?;
        Ok(server)
    }

    /// The state directory.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.directory.path().join("state"))?)
    }

    /// The plaintext `ops-key`.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// The listener's base URL; empty until [`Self::serve`] started it.
    pub(crate) fn base_url(&self) -> &str {
        self.base_url.get().map_or("", String::as_str)
    }

    /// `api_keys.json`.
    pub(crate) fn keys_file(&self) -> PathBuf {
        self.directory.path().join("state").join("api_keys.json")
    }
}

/// An HTTP client that does not follow redirects.
pub(crate) fn client() -> TestResult<Client> {
    let _installed = default_provider().install_default();
    Ok(Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// The first `data:` payload of an MCP response, or the body itself.
pub(crate) async fn payload(response: Response) -> TestResult<Value> {
    let body = response.error_for_status()?.text().await?;
    let text = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .find(|data| !data.is_empty())
        .unwrap_or(body.as_str());
    Ok(serde_json::from_str(text)?)
}

/// The JSON-RPC request `body` sent to `/mcp` with `key` and `session`.
pub(crate) async fn rpc(
    client: &Client,
    (base, key, session): (&str, &str, Option<&str>),
    body: &Value,
) -> TestResult<Response> {
    let mut request = client
        .post(format!("{base}/mcp"))
        .bearer_auth(key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(body);
    if let Some(id) = session {
        request = request.header("Mcp-Session-Id", id);
    }
    Ok(request.send().await?)
}

/// Opens an MCP session with `key`.
pub(crate) async fn mcp_session(client: &Client, base: &str, key: &str) -> TestResult<String> {
    let opened = rpc(
        client,
        (base, key, None),
        &json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"refresh","version":"1"}}}),
    )
    .await?
    .error_for_status()?;
    let session = opened
        .headers()
        .get("mcp-session-id")
        .ok_or("no MCP session id")?
        .to_str()?
        .to_owned();
    let _accepted: Response = rpc(
        client,
        (base, key, Some(&session)),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await?
    .error_for_status()?;
    Ok(session)
}

/// Calls `tool` with `arguments`; the tool's JSON answer.
pub(crate) async fn call(
    client: &Client,
    (base, key, session): (&str, &str, &str),
    (tool, arguments): (&str, Value),
) -> TestResult<Value> {
    let answer = payload(
        rpc(
            client,
            (base, key, Some(session)),
            &json!({"jsonrpc":"2.0","id":3_u32,"method":"tools/call","params":{"name":tool,"arguments":arguments}}),
        )
        .await?,
    )
    .await?;
    let text = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no tool text in {answer}"))?;
    Ok(serde_json::from_str(text)?)
}

/// The file's modification time.
pub(crate) fn modified(path: &Path) -> TestResult<SystemTime> {
    Ok(fs::metadata(path)?.modified()?)
}
