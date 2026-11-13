//! One `kcc serve` process over the fake router behind the hook relay, with an
//! administrator `alice` signed in to its Web UI and an administrator API key for MCP.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    audit::AUDIT_FILE_NAME,
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle};
use reqwest::{Client, Response, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use crate::{
    proxy::{self, Action},
    support::{PASSWORD, TestResult},
    web::Browser,
};

/// Upper bound for every wait on the child process.
pub(crate) const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// A running `kcc serve`; killed on drop if it is still running.
pub(crate) struct Served {
    /// Holds the state and configuration.
    directory: TempDir,
    /// The process.
    child: Child,
    /// The fake router.
    router: Handle,
    /// Web client.
    http: Client,
    /// Listener base URL.
    base: String,
    /// `alice`, signed in.
    alice: Browser,
    /// The administrator API key.
    key: String,
}

impl Drop for Served {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

impl Served {
    /// Starts the server with `server_extra` in `[server]` and MCP over HTTP when
    /// `mcp_http`, the relay running `hooks` built from the audit log's path, and signs
    /// `alice` in. Returns it with its stderr lines after `listening`.
    pub(crate) async fn start<H>(
        (server_extra, mcp_http): (&str, bool),
        hooks: H,
    ) -> TestResult<(Self, mpsc::Receiver<String>)>
    where
        H: FnOnce(PathBuf) -> Vec<(&'static [u8], Action)>,
    {
        let directory = TempDir::new()?;
        let home = directory.path();
        let (router_address, router) = FakeRouter::spawn().await?;
        let relay = proxy::spawn(
            router_address,
            hooks(home.join("state").join(AUDIT_FILE_NAME)),
        )
        .await?;
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let (config, key) = write_config(
            home,
            &format!("http://{relay}"),
            (port, server_extra, mcp_http),
        )?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_kcc"))
            .args(["serve", "--config", config.to_str().ok_or("path")?])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
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
        wait_line(&lines, "listening")?;
        let _installed = default_provider().install_default();
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(PROCESS_TIMEOUT)
            .build()?;
        let base = format!("http://127.0.0.1:{port}");
        let alice = Browser::sign_in(&http, &base, "alice").await?;
        let served = Self {
            directory,
            child,
            router,
            http,
            base,
            alice,
            key,
        };
        Ok((served, lines))
    }

    /// `alice` removes `Bridge0` in the CLI console: a management change.
    pub(crate) async fn management_change(&self) -> TestResult<Response> {
        self.alice
            .post(
                &self.http,
                &self.base,
                (
                    "/ui/r/router/console/cli/send",
                    &[
                        ("line", "no interface Bridge0"),
                        ("confirm", "yes"),
                        ("confirm_name", "router"),
                    ],
                ),
            )
            .await
    }

    /// What an MCP client needs: the HTTP client, the base URL and the API key.
    pub(crate) fn mcp(&self) -> (Client, String, String) {
        (self.http.clone(), self.base.clone(), self.key.clone())
    }

    /// Sends SIGTERM.
    pub(crate) fn terminate(&self) -> TestResult {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()?;
        if !status.success() {
            return Err("kill -TERM failed".into());
        }
        Ok(())
    }

    /// The fake router.
    pub(crate) const fn router(&self) -> &Handle {
        &self.router
    }

    /// The exit status within `limit`, or `None` while the process still runs.
    pub(crate) fn exit_within(&mut self, limit: Duration) -> TestResult<Option<ExitStatus>> {
        Ok(self.child.wait_timeout(limit)?)
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }
}

/// Waits until one of `lines` contains `needle`.
pub(crate) fn wait_line(lines: &mpsc::Receiver<String>, needle: &str) -> TestResult {
    while !lines.recv_timeout(PROCESS_TIMEOUT)?.contains(needle) {}
    Ok(())
}

/// Writes the state, the master key and `kcc.toml` for the router at `url`; returns the
/// configuration's path and the administrator API key.
fn write_config(
    home: &Path,
    url: &str,
    (port, extra, mcp_http): (u16, &str, bool),
) -> TestResult<(PathBuf, String)> {
    let password_file = kcc_testkit::write_secret_file(home, "router.password", DEFAULT_PASSWORD)?;
    let state = StateStore::open(&home.join("state"))?;
    let accounts = AccountStore::new(
        state.clone(),
        MasterKey::from_bytes([17_u8; 32]),
        Duration::from_mins(15),
        Arc::new(SystemClock::default()),
    );
    accounts.create(NewAccount::new(
        "alice".to_owned(),
        SecretString::from(PASSWORD),
        "admin".to_owned(),
    ))?;
    let created = create_api_key(&state, "mcp-key".to_owned(), "admin".to_owned(), 1)?;
    let key = home.join("master.key");
    fs::write(&key, [17_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    }
    let config = home.join("kcc.toml");
    fs::write(
        &config,
        format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n{extra}\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = {mcp_http}\nallow_destructive = true\ntoolsets = [\"core\", \"raw\"]\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"router\"\nurl = \"{url}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
            state.dir().display().to_string(),
            password_file.display().to_string()
        ),
    )?;
    Ok((config, expose_created_key(&created).to_owned()))
}
