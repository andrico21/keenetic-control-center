//! `kcc serve` with the dedicated MCP listener: it serves `/mcp` with an API key, a port
//! taken at start skips it with the reason logged while the Web UI serves, and SIGTERM
//! stops both listeners before the rest of the shutdown sequence.
//!
//! On Linux every child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the size
//! Windows gives the main thread.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[cfg(unix)]
#[path = "serve_listeners/early_signal.rs"]
mod early_signal;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[cfg(unix)]
#[expect(dead_code, reason = "only SIGTERM is sent here")]
#[path = "support/signal.rs"]
mod signal;
#[path = "support/spawning.rs"]
mod spawning;

use core::{error::Error, time::Duration};
#[cfg(unix)]
use std::net::TcpStream;
use std::{
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Instant,
};

use kcc_app::{
    api_keys::{create_api_key, expose_created_key},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MASTER_KEY_FILE_ENV,
};
use kcc_testkit::toml_text::path as toml_path;
use reqwest::{Client, StatusCode, header};
use rustls::crypto::ring::default_provider;
use serde_json::{Value, json};
use serve_port::{Start, await_ready, start_on_free_ports, stderr_lines};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Upper bound for a start and for each awaited log line.
const LIMIT: Duration = Duration::from_secs(30);

/// A `kcc serve` child; killed on drop.
struct Server {
    /// The process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every line read so far.
    seen: Vec<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// Reads lines until one contains `wanted`, for at most [`LIMIT`].
    fn until(&mut self, wanted: &str) -> TestResult {
        if self.seen.iter().any(|line| line.contains(wanted)) {
            return Ok(());
        }
        let deadline = Instant::now().checked_add(LIMIT).ok_or("deadline")?;
        loop {
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| {
                    format!("{error} waiting for {wanted:?}:\n{}", self.seen.join("\n"))
                })?;
            let found = line.contains(wanted);
            self.seen.push(line);
            if found {
                return Ok(());
            }
        }
    }

    /// The index of the first line read containing `wanted`.
    fn position(&self, wanted: &str) -> Option<usize> {
        self.seen.iter().position(|line| line.contains(wanted))
    }
}

/// State with an admin API key, a master key and a kcc.toml template.
struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// The plaintext API key.
    key: String,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let created = create_api_key(
            &state,
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            "listeners".to_owned(),
            "admin".to_owned(),
            1,
            None,
        )?;
        master_key::write(&directory.path().join("master.key"), [17_u8; 32])?;
        let _installed = default_provider().install_default();
        Ok(Self {
            directory,
            key: expose_created_key(&created).to_owned(),
        })
    }

    /// Writes kcc.toml for the main listener on `main` and the dedicated one on
    /// `dedicated`.
    fn configure(&self, main: u16, dedicated: u16) -> TestResult<PathBuf> {
        let config = self.directory.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {main}\nshutdown_timeout = \"1s\"\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\n\n[mcp.dedicated]\nenabled = true\nport = {dedicated}\n\n[observability]\nlog_format = \"json\"\n\n[state]\ndir = {}\n",
                toml_path(&self.directory.path().join("state"))
            ),
        )?;
        Ok(config)
    }

    /// `kcc serve --config <config>`, on Linux behind a 1 MiB main-thread stack.
    fn command(&self, path: &Path) -> TestResult<Command> {
        let home = self.directory.path();
        let kcc = env!("CARGO_BIN_EXE_kcc");
        let config = path.to_str().ok_or("non-UTF-8 path")?;
        let mut command = if cfg!(target_os = "linux") {
            let mut wrapped = spawning::command("sh");
            let _: &mut Command = wrapped.args(["-c", "ulimit -s 1024 && exec \"$0\" \"$@\"", kcc]);
            wrapped
        } else {
            spawning::command(kcc)
        };
        let _: &mut Command = command
            .args(["serve", "--config", config])
            .env_clear()
            .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env("LOCALAPPDATA", home.join("state-home"))
            .env("APPDATA", home.join("config"))
            .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        Ok(command)
    }

    /// Starts `kcc serve` with the dedicated listener on `dedicated` (a free port when
    /// `None`) and waits until the main listener serves; the ports and the server.
    fn serve(&self, dedicated: Option<u16>) -> TestResult<([u16; 2], Server)> {
        start_on_free_ports(|[main, free]| -> TestResult<Start<Server>> {
            let config = self.configure(main, dedicated.unwrap_or(free))?;
            let mut child = spawning::spawn(&mut self.command(&config)?)?;
            let lines = stderr_lines(&mut child)?;
            let listening = format!("listening on 127.0.0.1:{main}");
            Ok(
                match await_ready(&lines, |line| line.contains(&listening), LIMIT)? {
                    Start::Ready(seen) => Start::Ready(Server { child, lines, seen }),
                    Start::AddressInUse => Start::AddressInUse,
                },
            )
        })
        .map(|([main, free], server)| ([main, dedicated.unwrap_or(free)], server))
    }
}

/// A client with a bounded timeout.
fn client() -> TestResult<Client> {
    Ok(Client::builder().timeout(Duration::from_secs(10)).build()?)
}

/// The status of an MCP `initialize` at `port` with `key`.
async fn initialize(client: &Client, port: u16, key: &str) -> TestResult<StatusCode> {
    Ok(client
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .bearer_auth(key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"listeners","version":"1"}}}))
        .send()
        .await?
        .status())
}

/// Todo 26: the dedicated listener configured in kcc.toml answers `/mcp` with an API key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_configured_dedicated_listener_answers_mcp() -> TestResult {
    let fixture = Fixture::new()?;
    let ([_main, dedicated], mut server) = fixture.serve(None)?;

    server.until(&format!("listening on 127.0.0.1:{dedicated}"))?;

    assert_eq!(
        initialize(&client()?, dedicated, &fixture.key).await?,
        StatusCode::OK
    );
    Ok(())
}

/// Todo 26: a dedicated port taken at start skips the dedicated listener with the reason
/// logged; the Web UI serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_dedicated_port_is_skipped_with_the_reason_logged() -> TestResult {
    let fixture = Fixture::new()?;
    let held = TcpListener::bind(("127.0.0.1", 0))?;
    let ([main, _dedicated], mut server) = fixture.serve(Some(held.local_addr()?.port()))?;

    server.until("dedicated MCP listener skipped")?;

    let client = client()?;
    let login = client
        .get(format!("http://127.0.0.1:{main}/ui/login"))
        .send()
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    let skipped = server
        .position("dedicated MCP listener skipped")
        .ok_or("no skip line")?;
    let event: Value = serde_json::from_str(server.seen.get(skipped).ok_or("no skip line")?)?;
    assert!(
        event
            .pointer("/fields/reason")
            .and_then(Value::as_str)
            .is_some_and(|reason| !reason.is_empty()),
        "{event}"
    );
    drop(held);
    Ok(())
}

/// Todo 26: SIGTERM stops both listeners (the supervisor logs it) before the rest of the
/// shutdown sequence drains the jobs, and the process exits 0.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_stops_both_listeners_before_the_shutdown_sequence() -> TestResult {
    let fixture = Fixture::new()?;
    let ([_main, dedicated], mut server) = fixture.serve(None)?;
    server.until(&format!("listening on 127.0.0.1:{dedicated}"))?;

    signal::send(&server.child, signal::Signal::Terminate)?;
    server.until("jobs drained")?;
    let status = server.child.wait()?;

    let stopped = server
        .position("listeners stopped")
        .ok_or("no listeners-stopped line")?;
    let drained = server
        .position("jobs drained")
        .ok_or("no jobs-drained line")?;
    assert!(stopped < drained, "{}", server.seen.join("\n"));
    assert!(status.success(), "{status:?}");
    assert!(
        TcpStream::connect(("127.0.0.1", dedicated)).is_err(),
        "the dedicated listener still serves"
    );
    Ok(())
}
