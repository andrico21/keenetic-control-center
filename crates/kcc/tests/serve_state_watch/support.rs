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
    io::{BufRead as _, BufReader},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Instant,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::block_in_place;

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
    /// Base URL of the listener.
    base: String,
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
            accounts.create(NewAccount::new(
                name.to_owned(),
                SecretString::from(PASSWORD),
                role.to_owned(),
            ))?;
        }
        let created = create_api_key(&state, KEY_NAME.to_owned(), "viewer".to_owned(), 1)?;
        let master = directory.path().join("master.key");
        fs::write(&master, [17_u8; 32])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&master, fs::Permissions::from_mode(0o600))?;
        }
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let config = directory.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\n\n[state]\ndir = {:?}\n\n[observability]\nlog_level = \"info,rmcp=warn,rmcp_server_kit=info,{RELOAD}=debug,{WATCH}=debug\"\nlog_format = \"json\"\n",
                state.dir().display().to_string(),
            ),
        )?;
        let _installed = default_provider().install_default();
        Ok(Self {
            directory,
            config,
            base: format!("http://127.0.0.1:{port}"),
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_kcc"));
        let _configured: &mut Command = command
            .args(["--config", self.config.to_str().ok_or("path")?])
            .args(arguments)
            .env_clear()
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
            .env("USER", "ops-cli")
            .env("LANG", "C");
        Ok(command)
    }

    /// Starts `kcc serve` and waits until it listens.
    pub(crate) fn serve(&self) -> TestResult<Server> {
        let mut child = self
            .kcc(&["serve"])?
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("child stderr")?;
        let (sender, lines) = mpsc::channel();
        drop(thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        }));
        let mut server = Server {
            child,
            lines,
            events: Vec::new(),
        };
        let listening = server.wait_event(PROCESS_TIMEOUT, |event| {
            event
                .pointer("/fields/message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("listening"))
        })?;
        let started = |event: &Value| {
            event.get("target").and_then(Value::as_str) == Some(WATCH)
                && event.pointer("/fields/interval_ms").is_some()
        };
        let watching = server.saw(started) || server.wait_event(PROCESS_TIMEOUT, started)?;
        if !(listening && watching) {
            return Err(format!(
                "kcc serve did not start (listening {listening}, watching {watching})"
            )
            .into());
        }
        Ok(server)
    }

    /// Runs the CLI with `arguments`; fails unless it exits 0.
    pub(crate) fn cli(&self, arguments: &[&str]) -> TestResult {
        let output = self.kcc(arguments)?.stdin(Stdio::null()).output()?;
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

    /// The listener's base URL.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The status of an MCP `initialize` made with the API key.
    pub(crate) async fn mcp_status(&self) -> TestResult<StatusCode> {
        Ok(self
            .http
            .post(format!("{}/mcp", self.base))
            .bearer_auth(&self.key)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"watch","version":"1"}}}))
            .send()
            .await?
            .status())
    }
}
