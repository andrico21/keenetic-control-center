//! A `kcc serve` process with JSON logs, the `kcc` CLI on the same state, and clients
//! for its Web UI and MCP.
//!
//! The state holds the administrator `alice`, the operator `bob` and the API key
//! `watch-key`; no router is configured.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{
    env, fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{OnceLock, mpsc},
    time::Instant,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::block_in_place;

use crate::{
    master_key,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Password of every account.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// The API key's name.
pub(crate) const KEY_NAME: &str = "watch-key";

/// How long a change made on disk may take to reach the running server.
pub(crate) const PROPAGATION: Duration = Duration::from_secs(5);

/// Upper bound for starting the server and for each CLI run.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// The log target of an applied change.
pub(crate) const RELOAD: &str = "kcc::state_reload";

/// The log target of the state watcher's other observations.
pub(crate) const WATCH: &str = "kcc::state_watch";

/// The running server; killed on drop.
pub(crate) struct Server {
    /// The `kcc serve` process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every JSON log event read so far.
    events: Vec<Value>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Whether `event` has `target` and names the state file `file`.
pub(crate) fn about(event: &Value, target: &str, file: &str) -> bool {
    event.get("target").and_then(Value::as_str) == Some(target)
        && event.pointer("/fields/file").and_then(Value::as_str) == Some(file)
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

/// Whether `event` is a warning.
pub(crate) fn warning(event: &Value) -> bool {
    event.get("level").and_then(Value::as_str) == Some("WARN")
}

impl Server {
    /// Waits at most `limit` for a new log event matching `wanted`; `false` when none
    /// came. Every event read meanwhile is kept for [`Server::saw`].
    pub(crate) fn wait_event<F>(&mut self, limit: Duration, wanted: F) -> TestResult<bool>
    where
        F: Fn(&Value) -> bool,
    {
        let deadline = Instant::now()
            .checked_add(limit)
            .ok_or("deadline overflow")?;
        block_in_place(|| {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(line) = self.lines.recv_timeout(remaining) else {
                    return Ok(false);
                };
                let Ok(event) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let found = wanted(&event);
                self.events.push(event);
                if found {
                    return Ok(true);
                }
            }
        })
    }

    /// Whether any event read so far matches `wanted`.
    pub(crate) fn saw<F>(&self, wanted: F) -> bool
    where
        F: Fn(&Value) -> bool,
    {
        self.events.iter().any(wanted)
    }
}

/// State, configuration and the clients of one server.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// `kcc.toml`.
    config: PathBuf,
    /// `kcc.toml` with [`PORT_HOLE`] for the listen port.
    template: String,
    /// Base URL of the listener, once it serves.
    base: OnceLock<String>,
    /// The plaintext API key.
    key: String,
    /// HTTP client that does not follow redirects.
    http: Client,
}

impl Fixture {
    /// Writes the state and the configuration.
    pub(crate) fn new() -> TestResult<Self> {
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
        let created = create_api_key(
            &state,
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            KEY_NAME.to_owned(),
            "viewer".to_owned(),
            1,
        )?;
        master_key::write(&directory.path().join("master.key"), [17_u8; 32])?;
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\n\n[state]\ndir = {:?}\n\n[observability]\nlog_level = \"info,rmcp=warn,rmcp_server_kit=info,{RELOAD}=debug,{WATCH}=debug\"\nlog_format = \"json\"\n",
            state.dir().display().to_string(),
        );
        let config = directory.path().join("kcc.toml");
        fs::write(&config, template.replace(PORT_HOLE, "1024"))?;
        let _installed = default_provider().install_default();
        Ok(Self {
            directory,
            config,
            template,
            base: OnceLock::new(),
            key: expose_created_key(&created).to_owned(),
            http: Client::builder()
                .redirect(Policy::none())
                .timeout(PROCESS_TIMEOUT)
                .build()?,
        })
    }

    /// `kcc` with this fixture's configuration and environment.
    fn kcc(&self, arguments: &[&str]) -> TestResult<Command> {
        let home = self.directory.path();
        let mut command = spawning::command(env!("CARGO_BIN_EXE_kcc"));
        let _configured: &mut Command = command
            .args(["--config", self.config.to_str().ok_or("path")?])
            .args(arguments)
            .env_clear()
            // Windows sockets fail to load their provider without SystemRoot.
            .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
            .env("USER", "ops-cli")
            .env("LANG", "C");
        Ok(command)
    }

    /// Starts `kcc serve` on a free port and waits until it listens and watches the state.
    pub(crate) fn serve(&self) -> TestResult<Server> {
        let ([port], mut server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            fs::write(
                &self.config,
                self.template.replace(PORT_HOLE, &port.to_string()),
            )?;
            let mut child = spawning::spawn(
                self.kcc(&["serve"])?
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            )?;
            let lines = stderr_lines(&mut child)?;
            let mut server = Server {
                child,
                lines,
                events: Vec::new(),
            };
            let started = await_ready(&server.lines, listening, PROCESS_TIMEOUT)?;
            Ok(match started {
                Start::Ready(seen) => {
                    server.events = seen
                        .iter()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect();
                    Start::Ready(server)
                }
                Start::AddressInUse => Start::AddressInUse,
            })
        })?;
        let started = |event: &Value| {
            event.get("target").and_then(Value::as_str) == Some(WATCH)
                && event.pointer("/fields/interval_ms").is_some()
        };
        if !(server.saw(started) || server.wait_event(PROCESS_TIMEOUT, started)?) {
            return Err("kcc serve listens but does not watch the state".into());
        }
        self.base
            .set(format!("http://127.0.0.1:{port}"))
            .map_err(|_served| "the fixture serves once")?;
        Ok(server)
    }

    /// Runs the CLI with `arguments`; fails unless it exits 0.
    pub(crate) fn cli(&self, arguments: &[&str]) -> TestResult {
        let output = spawning::spawn(
            self.kcc(arguments)?
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?
        .wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "kcc {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Writes `secret` to a private file for `--password-file`.
    pub(crate) fn secret_file(&self, name: &str, secret: &str) -> TestResult<String> {
        Ok(
            kcc_testkit::write_secret_file(self.directory.path(), name, secret)?
                .to_str()
                .ok_or("path")?
                .to_owned(),
        )
    }

    /// The state directory.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.directory.path().join("state"))?)
    }

    /// The state file `name`.
    pub(crate) fn file(&self, name: &str) -> PathBuf {
        self.directory.path().join("state").join(name)
    }

    /// The HTTP client.
    pub(crate) const fn http(&self) -> &Client {
        &self.http
    }

    /// The listener's base URL; empty until [`Self::serve`] started it.
    pub(crate) fn base(&self) -> &str {
        self.base.get().map_or("", String::as_str)
    }

    /// The status of an MCP `initialize` made with the API key.
    pub(crate) async fn mcp_status(&self) -> TestResult<StatusCode> {
        Ok(self
            .http
            .post(format!("{}/mcp", self.base()))
            .bearer_auth(&self.key)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"watch","version":"1"}}}))
            .send()
            .await?
            .status())
    }
}
