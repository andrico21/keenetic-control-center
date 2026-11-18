//! Hermetic process environment and fake-router helpers for the CLI tests.

use core::{error::Error, net::SocketAddr, time::Duration};
use std::{
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
};

use kcc_app::secrets::MASTER_KEY_FILE_ENV;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use crate::{master_key, spawning};

/// Fallible test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The OS user every test process runs as.
pub(crate) const USER: &str = "tester";

/// Longest time one `kcc` process may run.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(90);

/// The outcome of one `kcc` process.
#[derive(Debug)]
pub(crate) struct Run {
    /// Exit code.
    pub code: i32,
    /// Everything written to stdout.
    pub stdout: String,
    /// Everything written to stderr.
    pub stderr: String,
}

/// A temporary configuration, state directory and master key.
pub(crate) struct Env {
    /// Owner of every file.
    directory: TempDir,
}

impl Env {
    /// Writes `kcc.toml` with loopback routers allowed, the state directory, and `body`.
    pub(crate) fn new(body: &str) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let env = Self { directory };
        master_key::write(&env.path("master.key"), [17_u8; 32])?;
        env.write_config(body)?;
        Ok(env)
    }

    /// Replaces `kcc.toml` with the common header and `body`.
    pub(crate) fn write_config(&self, body: &str) -> TestResult {
        let state = self.state_dir().display().to_string();
        let text =
            format!("[outbound]\nallow_loopback = true\n\n[state]\ndir = {state:?}\n\n{body}");
        fs::write(self.path("kcc.toml"), text)?;
        Ok(())
    }

    /// A path inside the temporary directory.
    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.path("state")
    }

    /// Writes `content` to `name` readable by its owner only, as kcc requires of the
    /// secret files it reads, and returns its path.
    pub(crate) fn write(&self, name: &str, content: &str) -> Result<PathBuf, Box<dyn Error>> {
        Ok(kcc_testkit::write_secret_file(
            self.directory.path(),
            name,
            content,
        )?)
    }

    /// Runs `kcc --config <kcc.toml> <args>`.
    pub(crate) fn kcc(&self, args: &[&str]) -> Result<Run, Box<dyn Error>> {
        let config = self.path("kcc.toml");
        let mut all = vec!["--config", config.to_str().ok_or("non-UTF-8 path")?];
        all.extend_from_slice(args);
        self.kcc_bare(&all)
    }

    /// Runs `kcc <args>` without `--config`.
    pub(crate) fn kcc_bare(&self, args: &[&str]) -> Result<Run, Box<dyn Error>> {
        let child = spawning::spawn(&mut self.command(args))?;
        finish(child)
    }

    /// The hermetic command line of `kcc <args>`, for long-running children.
    pub(crate) fn command(&self, args: &[&str]) -> Command {
        let home = self.path("home");
        let mut command = spawning::command(env!("CARGO_BIN_EXE_kcc"));
        let _: &mut Command = command
            .args(args)
            .env_clear()
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env(MASTER_KEY_FILE_ENV, self.path("master.key"))
            .env("USER", USER)
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// Waits for `child` with a deadline and collects its output.
fn finish(mut child: Child) -> Result<Run, Box<dyn Error>> {
    let mut stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let mut stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out_reader = thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).map(|_read| text)
    });
    let err_reader = thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).map(|_read| text)
    });
    let Some(status) = child.wait_timeout(PROCESS_TIMEOUT)? else {
        child.kill()?;
        let _: ExitStatus = child.wait()?;
        return Err("kcc did not exit before the deadline".into());
    };
    Ok(Run {
        code: status.code().ok_or("kcc was killed by a signal")?,
        stdout: out_reader
            .join()
            .map_err(|_panic| "stdout reader panicked")??,
        stderr: err_reader
            .join()
            .map_err(|_panic| "stderr reader panicked")??,
    })
}

/// One `[[routers]]` entry for a fake router at `address`.
pub(crate) fn router(name: &str, address: SocketAddr, password_file: &Path) -> String {
    format!(
        "[[routers]]\nname = {name:?}\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {:?}\n\n",
        password_file.display().to_string()
    )
}
