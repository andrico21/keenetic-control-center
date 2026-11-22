//! A `kcc serve` child with the Web UI over a fake router: the administrator `alice`, an
//! administrator API key, a browser on the MCP settings page and an MCP client.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, time::Duration};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile, toml_text};
use reqwest::{Client, Response, StatusCode, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::{
    browser::Browser,
    master_key,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Password of `alice`.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// Upper bound for a start and for one request.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The master key's bytes.
const KEY: [u8; 32] = [31_u8; 32];

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// A `kcc serve` child; killed on drop.
pub(crate) struct Server {
    /// The process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every line read so far.
    seen: Vec<String>,
    /// The main listener's base URL.
    base: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// The main listener's base URL.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// How many lines read so far contain `wanted`, after reading every line written.
    pub(crate) fn count(&mut self, wanted: &str) -> usize {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen
            .iter()
            .filter(|line| line.contains(wanted))
            .count()
    }
}

/// The state, the fake router and the configuration.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// The fake router, served while the fixture lives.
    _router: Handle,
    /// The configuration without the main port.
    template: String,
    /// The plaintext API key.
    key: String,
    /// HTTP client that does not follow redirects.
    http: Client,
}

impl Fixture {
    /// Writes the state, the account `alice`, an API key and the configuration.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        AccountStore::new(
            state.clone(),
            MasterKey::from_bytes(KEY),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        )
        .create(
            &admin(),
            NewAccount::new(
                "alice".to_owned(),
                SecretString::from(PASSWORD),
                "admin".to_owned(),
            ),
        )?;
        let created = create_api_key(
            &state,
            &admin(),
            "settings".to_owned(),
            "admin".to_owned(),
            1,
            None,
        )?;
        master_key::write(&directory.path().join("master.key"), KEY)?;
        let (address, router) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {{main}}\nshutdown_timeout = \"1s\"\n\n[web]\nenabled = true\n\n[outbound]\nallow_loopback = true\n\n[mcp]\ntoolsets = [\"core\", \"system-admin\"]\n\n[state]\ndir = {}\n\n[observability]\nlog_level = \"info\"\nlog_format = \"json\"\n\n[[routers]]\nname = \"fake\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {}\n",
            toml_text::path(state.dir()),
            toml_text::path(&password),
        );
        let _installed = default_provider().install_default();
        Ok(Self {
            key: expose_created_key(&created).to_owned(),
            directory,
            _router: router,
            template,
            http: Client::builder()
                .redirect(Policy::none())
                .timeout(LIMIT)
                .build()?,
        })
    }

    /// The bytes of `mcp_settings.json`, `None` while it does not exist.
    pub(crate) fn settings(&self) -> TestResult<Option<Vec<u8>>> {
        let path = self
            .directory
            .path()
            .join("state")
            .join("mcp_settings.json");
        Ok(if path.exists() {
            Some(fs::read(path)?)
        } else {
            None
        })
    }

    /// The HTTP client.
    pub(crate) const fn http(&self) -> &Client {
        &self.http
    }

    /// `kcc serve --config <config>`, on Linux behind a 1 MiB main-thread stack, the size
    /// Windows gives the main thread.
    fn command(&self, config: &Path) -> TestResult<Command> {
        let home = self.directory.path();
        let kcc = env!("CARGO_BIN_EXE_kcc");
        let mut command = if cfg!(target_os = "linux") {
            let mut wrapped = spawning::command("sh");
            let _: &mut Command = wrapped.args(["-c", "ulimit -s 1024 && exec \"$0\" \"$@\"", kcc]);
            wrapped
        } else {
            spawning::command(kcc)
        };
        let _: &mut Command = command
            .args([
                "serve",
                "--config",
                config.to_str().ok_or("non-UTF-8 path")?,
            ])
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

    /// Starts `kcc serve` on a free main port and waits until it listens.
    pub(crate) fn serve(&self) -> TestResult<Server> {
        let config: PathBuf = self.directory.path().join("kcc.toml");
        let ([_port], server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            fs::write(&config, self.template.replace("{main}", &port.to_string()))?;
            let mut child = spawning::spawn(&mut self.command(&config)?)?;
            let lines = stderr_lines(&mut child)?;
            let listening = format!("listening on 127.0.0.1:{port}");
            Ok(
                match await_ready(&lines, |line| line.contains(&listening), LIMIT)? {
                    Start::Ready(seen) => Start::Ready(Server {
                        child,
                        lines,
                        seen,
                        base: format!("http://127.0.0.1:{port}"),
                    }),
                    Start::AddressInUse => Start::AddressInUse,
                },
            )
        })?;
        Ok(server)
    }

    /// `alice` signed in at `base`.
    pub(crate) async fn sign_in(&self, base: &str) -> TestResult<Browser> {
        Browser::sign_in(&self.http, base, ("alice", PASSWORD)).await
    }

    /// The body of a new MCP session's `kcc_system_write` reboot of the fake router,
    /// unconfirmed, at `base`: `destructive_disabled` or `confirm_required` in it.
    pub(crate) async fn reboot(&self, base: &str) -> TestResult<String> {
        let opened = self
            .rpc((base, None), &json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"settings","version":"1"}}}))
            .await?;
        let session = opened
            .headers()
            .get("mcp-session-id")
            .ok_or("no MCP session id")?
            .to_str()?
            .to_owned();
        drop(
            self.rpc(
                (base, Some(&session)),
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await?,
        );
        let call = json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/call","params":{"name":"kcc_system_write","arguments":{"host":"fake","op":"reboot"}}});
        Ok(self
            .rpc((base, Some(&session)), &call)
            .await?
            .text()
            .await?)
    }

    /// The status of an MCP `initialize` at `port` with the API key.
    pub(crate) async fn initialize(&self, port: u16) -> TestResult<StatusCode> {
        let body = json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"settings","version":"1"}}});
        Ok(self
            .rpc((&format!("http://127.0.0.1:{port}"), None), &body)
            .await?
            .status())
    }

    /// The JSON-RPC request `body` to `/mcp` at `base` in `session`.
    async fn rpc(
        &self,
        (base, session): (&str, Option<&str>),
        body: &Value,
    ) -> TestResult<Response> {
        let mut request = self
            .http
            .post(format!("{base}/mcp"))
            .bearer_auth(&self.key)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .json(body);
        if let Some(id) = session {
            request = request.header("Mcp-Session-Id", id);
        }
        Ok(request.send().await?)
    }
}
