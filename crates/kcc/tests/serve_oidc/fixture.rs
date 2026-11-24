//! The OIDC suite's `kcc serve` child and its state: roles, API keys, the fake identity
//! provider and its CA bundle stored as the Web upload stores it.

use core::{mem, time::Duration};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use kcc_app::{
    api_keys::{create_api_key, expose_created_key},
    mcp_settings::idp_ca::store_oidc_ca,
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    secrets::MASTER_KEY_FILE_ENV,
};
use kcc_testkit::{
    fake_idp::{FakeIdp, tokens::Claims},
    toml_text::path as toml_path,
};
use reqwest::{Client, StatusCode};
use rustls::crypto::ring::default_provider;
use serde_json::json;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use crate::{
    TestResult, master_key,
    serve_port::{Start, await_ready, free_ports, start_on_free_ports, stderr_lines},
    spawning,
};

/// Upper bound for a start and for each awaited log line.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The audience the provider's tokens name for kcc.
pub(crate) const AUDIENCE: &str = "kcc-mcp";

/// The group mapped to the built-in `operator` role.
pub(crate) const ADMINS: &str = "kcc-admins";

/// The group mapped to the custom `lab` role (read, write, destructive).
pub(crate) const LAB: &str = "kcc-lab";

/// The `[mcp.auth.oidc]` allowlist admitting the provider on `localhost`.
pub(crate) const ALLOW_LOCALHOST: &str = "ssrf_allow_hosts = [\"localhost\"]";

/// A `kcc serve` child; killed on drop.
pub(crate) struct Server {
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
    /// Stops the child and returns every line it wrote.
    pub(crate) fn finish(mut self) -> TestResult<Vec<String>> {
        self.child.kill()?;
        let _status = self.child.wait()?;
        let rest = drained(&self.lines)?;
        self.seen.extend(rest);
        Ok(mem::take(&mut self.seen))
    }
}

/// State with the custom role `lab`, an `operator` key, the provider and its CA bundle.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests sign tokens with the provider and compare with the key's tools"
)]
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// The identity provider.
    pub(crate) idp: FakeIdp,
    /// A key of the built-in `operator` role.
    pub(crate) operator_key: String,
}

impl Fixture {
    /// The state, the keys and a running provider whose CA bundle is stored.
    pub(crate) async fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        state.update(|roles: &mut RolesDocument| {
            roles.roles.push(Role::new(
                "lab".to_owned(),
                [Permission::Read, Permission::Write, Permission::Destructive],
                vec!["*".to_owned()],
            ));
        })?;
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        let created = create_api_key(
            &state,
            &admin,
            "operator-key".to_owned(),
            "operator".to_owned(),
            1,
            None,
        )?;
        let idp = FakeIdp::spawn().await?;
        let _subjects = store_oidc_ca(&state, idp.ca_pem().as_bytes())?;
        master_key::write(&directory.path().join("master.key"), [23_u8; 32])?;
        Ok(Self {
            directory,
            idp,
            operator_key: expose_created_key(&created).to_owned(),
        })
    }

    /// The state directory.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.directory.path().join("state"))?)
    }

    /// The issuer the provider's tokens name.
    pub(crate) fn issuer(&self) -> String {
        format!("https://localhost:{}/realms/kcc", self.idp.address().port())
    }

    /// Writes kcc.toml for a plain loopback main listener on `port` signing in with the
    /// provider, `allowlist` in `[mcp.auth.oidc]`.
    fn configure(&self, port: u16, allowlist: &str) -> TestResult<PathBuf> {
        let config = self.directory.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\nshutdown_timeout = \"1s\"\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\ntoolsets = [\"core\", \"system-admin\"]\n\n[mcp.auth.main]\noauth = \"external\"\n\n[mcp.auth.oidc]\nissuer = \"{}\"\naudience = \"{AUDIENCE}\"\njwks_uri = \"{}\"\nrole_claim = \"groups\"\nallowed_algorithms = [\"ES256\"]\n{allowlist}\n\n[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"{ADMINS}\"\nrole = \"operator\"\n\n[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"{LAB}\"\nrole = \"lab\"\n\n[observability]\nlog_format = \"json\"\n\n[state]\ndir = {}\n",
                self.issuer(),
                self.idp.jwks_uri(),
                toml_path(&self.directory.path().join("state"))
            ),
        )?;
        Ok(config)
    }

    /// `kcc serve --config <config>`, on Linux behind a 1 MiB main-thread stack.
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

    /// Starts `kcc serve` admitting the provider on `localhost` and waits until the main
    /// listener serves; its port and the server.
    pub(crate) fn serve(&self) -> TestResult<(u16, Server)> {
        let ([port], server) =
            start_on_free_ports(|[port]: [u16; 1]| -> TestResult<Start<Server>> {
                let config = self.configure(port, ALLOW_LOCALHOST)?;
                let mut child = spawning::spawn(&mut self.command(&config)?)?;
                let lines = stderr_lines(&mut child)?;
                let listening = format!("listening on 127.0.0.1:{port}");
                Ok(
                    match await_ready(&lines, |line| line.contains(&listening), LIMIT)? {
                        Start::Ready(seen) => Start::Ready(Server { child, lines, seen }),
                        Start::AddressInUse => Start::AddressInUse,
                    },
                )
            })?;
        Ok((port, server))
    }

    /// Runs `kcc serve` without kcc.toml's allowlist until it exits; its status and every
    /// line it wrote.
    pub(crate) fn serve_without_allowlist(&self) -> TestResult<(ExitStatus, Vec<String>)> {
        let [port] = free_ports()?;
        let config = self.configure(port, "")?;
        let mut child = spawning::spawn(&mut self.command(&config)?)?;
        let lines = stderr_lines(&mut child)?;
        let exited = child.wait_timeout(LIMIT)?;
        drop(child.kill());
        let status = exited.ok_or("kcc serve did not exit")?;
        Ok((status, drained(&lines)?))
    }

    /// Claims from the provider for kcc, for `sub` in `groups`, valid for an hour.
    pub(crate) fn claims(&self, sub: &str, groups: &[&str]) -> TestResult<Claims> {
        let now = now()?;
        let mut claims = Claims::new(&self.issuer(), AUDIENCE, sub, now.saturating_add(3600));
        claims.groups = Some(groups.iter().map(|group| (*group).to_owned()).collect());
        Ok(claims)
    }
}

/// Every line `lines` still delivers until the child's stderr closes, for at most
/// [`LIMIT`].
fn drained(lines: &mpsc::Receiver<String>) -> TestResult<Vec<String>> {
    let deadline = Instant::now().checked_add(LIMIT).ok_or("deadline")?;
    let mut rest = Vec::new();
    while let Ok(line) = lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        rest.push(line);
    }
    Ok(rest)
}

/// Now, in Unix seconds.
pub(crate) fn now() -> TestResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// A plain HTTP client keeping no idle connection.
pub(crate) fn client() -> TestResult<Client> {
    let _installed = default_provider().install_default();
    Ok(Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(15))
        .build()?)
}

/// The status of an MCP `initialize` on `port` with the bearer `token`.
pub(crate) async fn initialize(client: &Client, port: u16, token: &str) -> TestResult<StatusCode> {
    Ok(client
        .post(format!("{}/mcp", url(port)))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"oidc","version":"1"}}}))
        .send()
        .await?
        .status())
}

/// The base URL of the main listener on `port`.
pub(crate) fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}
