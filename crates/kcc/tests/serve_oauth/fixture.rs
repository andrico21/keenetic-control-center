//! A `kcc serve` child on a loopback main listener, so the kcc issuer is
//! `http://localhost:<port>`: the administrator `alice`, the viewer `vera`, the operators
//! `olga`, `dora` and `mira`, no router.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, PoisonError, mpsc},
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    audit::{AuditEntry, read_entries},
    mcp_auth::grants::GrantsDocument,
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::toml_text;
use reqwest::{Client, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::SecretString;
use tempfile::TempDir;

use crate::{
    master_key,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Password of every account.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// Upper bound for a start and for one request.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The master key's bytes.
const KEY: [u8; 32] = [41_u8; 32];

/// The administrator role.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// How the child is configured.
#[derive(Clone, Copy)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "each test sets what differs from the default"
)]
pub(crate) struct Options {
    /// Whether the main listener signs in with kcc accounts.
    pub(crate) kcc: bool,
    /// The log level.
    pub(crate) level: &'static str,
}

impl Options {
    /// kcc sign-in on the main listener, `info` logs.
    pub(crate) const KCC: Self = Self {
        kcc: true,
        level: "info",
    };
}

/// A `kcc serve` child; killed on drop.
pub(crate) struct Server {
    /// The process.
    child: Child,
    /// Its stderr lines.
    lines: Mutex<mpsc::Receiver<String>>,
    /// Every line read so far.
    seen: Vec<String>,
    /// The main listener's port.
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// `http://127.0.0.1:<port>`.
    pub(crate) fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The issuer kcc advertises: `http://localhost:<port>`.
    pub(crate) fn issuer(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    /// The canonical MCP resource the kit advertises.
    pub(crate) fn resource(&self) -> String {
        format!("{}/mcp", self.base())
    }

    /// Every line written so far.
    pub(crate) fn log(&mut self) -> String {
        let lines = self.lines.get_mut().unwrap_or_else(PoisonError::into_inner);
        while let Ok(line) = lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }

    /// Reads lines until one contains `wanted`, for at most [`LIMIT`]; the line.
    pub(crate) fn wait_for(&mut self, wanted: &str) -> TestResult<String> {
        if let Some(line) = self.seen.iter().find(|line| line.contains(wanted)) {
            return Ok(line.clone());
        }
        let lines = self.lines.get_mut().unwrap_or_else(PoisonError::into_inner);
        loop {
            let line = lines.recv_timeout(LIMIT)?;
            self.seen.push(line.clone());
            if line.contains(wanted) {
                return Ok(line);
            }
        }
    }
}

/// The state, the accounts and the configuration.
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// HTTP client that does not follow redirects.
    http: Client,
}

impl Fixture {
    /// Writes the state with `alice` (admin), `vera` (viewer), `olga`, `dora` and `mira`
    /// (operators).
    pub(crate) fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        let _installed = default_provider().install_default();
        let fixture = Self {
            http: Client::builder()
                .redirect(Policy::none())
                .timeout(LIMIT)
                .build()?,
            directory,
        };
        let accounts = fixture.accounts()?;
        for (name, role) in [
            ("alice", "admin"),
            ("vera", "viewer"),
            ("olga", "operator"),
            ("dora", "operator"),
            ("mira", "operator"),
        ] {
            accounts.create(
                &admin(),
                NewAccount::new(
                    name.to_owned(),
                    SecretString::from(PASSWORD),
                    role.to_owned(),
                ),
            )?;
        }
        master_key::write(&fixture.directory.path().join("master.key"), KEY)?;
        Ok(fixture)
    }

    /// The HTTP client.
    pub(crate) const fn http(&self) -> &Client {
        &self.http
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }

    /// The state store, as the child opens it.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.state_dir())?)
    }

    /// The account store over the child's state and master key.
    pub(crate) fn accounts(&self) -> TestResult<AccountStore> {
        Ok(AccountStore::new(
            self.state()?,
            MasterKey::from_bytes(KEY),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        ))
    }

    /// The master key.
    pub(crate) fn key() -> MasterKey {
        MasterKey::from_bytes(KEY)
    }

    /// The grants file as it is now.
    pub(crate) fn grants(&self) -> TestResult<GrantsDocument> {
        Ok(self.state()?.read::<GrantsDocument>()?.unwrap_or_default())
    }

    /// The audit entries written so far.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(read_entries(&self.state_dir())?)
    }

    /// Every byte of every state file under the state directory; `*.lock` files are left
    /// out, they hold no state and Windows refuses to read one a live server holds.
    pub(crate) fn state_bytes(&self) -> TestResult<Vec<u8>> {
        bytes_below(&self.state_dir())
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

    /// The configuration for `options` on the main `port`.
    fn config(&self, options: Options, port: u16) -> String {
        let sign_in = if options.kcc {
            "\n[mcp.auth.main]\noauth = \"kcc\"\n"
        } else {
            ""
        };
        format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\nshutdown_timeout = \"1s\"\n\n[web]\nenabled = true\n\n[mcp]\ntoolsets = [\"core\"]\n{sign_in}\n[state]\ndir = {}\n\n[observability]\nlog_level = \"{}\"\nlog_format = \"json\"\n",
            toml_text::path(&self.state_dir()),
            options.level,
        )
    }

    /// Starts `kcc serve` with `options` on a free main port and waits until it listens.
    pub(crate) fn serve(&self, options: Options) -> TestResult<Server> {
        let config: PathBuf = self.directory.path().join("kcc.toml");
        let ([_port], server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
            fs::write(&config, self.config(options, port))?;
            let mut child = spawning::spawn(&mut self.command(&config)?)?;
            let lines = stderr_lines(&mut child)?;
            let listening = format!("listening on 127.0.0.1:{port}");
            Ok(
                match await_ready(&lines, |line| line.contains(&listening), LIMIT)? {
                    Start::Ready(seen) => Start::Ready(Server {
                        child,
                        lines: Mutex::new(lines),
                        seen,
                        port,
                    }),
                    Start::AddressInUse => Start::AddressInUse,
                },
            )
        })?;
        Ok(server)
    }
}

/// Every byte of every file below `root`, lock files left out.
fn bytes_below(root: &Path) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "lock") {
                bytes.extend(fs::read(path)?);
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{TestResult, bytes_below, fs};

    /// Todo 31: a lock file (held and unreadable on Windows) never reaches the scan; the
    /// state file does.
    #[test]
    fn lock_files_are_left_out_of_the_state_bytes() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("state.json"), b"state-content")?;
        fs::write(directory.path().join("x.lock"), b"lock-marker")?;
        let bytes = bytes_below(directory.path())?;
        let text = String::from_utf8(bytes)?;
        assert!(text.contains("state-content"), "{text}");
        assert!(!text.contains("lock-marker"), "{text}");
        Ok(())
    }
}
