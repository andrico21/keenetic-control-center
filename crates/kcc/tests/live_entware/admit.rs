//! The live gate of the Entware suites: the test-device profile without contact, then the
//! serial through `show identification`; and the temporary kcc home the suites drive the
//! built `kcc` from.

use core::time::Duration;
use std::{
    env, fs,
    io::Read as _,
    path::PathBuf,
    process::{Child, Stdio},
    thread,
};

use kcc_app::{secrets::MASTER_KEY_FILE_ENV, settings::OutboundConfig};
use kcc_testkit::{
    capture::{Connection, connect},
    toml_text,
};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;
use zeroize::Zeroizing;

use super::{
    TestResult,
    contract::Base,
    live_gate::{admission, allowlisted},
    master_key, spawning,
};

/// The router id of the admitted profile in the temporary kcc home.
pub(crate) const ROUTER: &str = "live-entware";

/// Longest time one `kcc` process may run (a setup with a component reboot and a 15-minute
/// installer wait stays below it).
const PROCESS_TIMEOUT: Duration = Duration::from_mins(40);

/// An admitted test router.
pub(crate) struct Admitted {
    /// Authenticated connection for the suites' own reads.
    pub connection: Connection,
    /// The temporary kcc home naming only this router.
    pub home: Home,
}

/// Checks the profile without contacting the router, then reads the serial; nothing else
/// is sent before both pass.
///
/// # Errors
/// Returns a [`super::live_gate::Refusal`], configuration, file or transport failures.
// NOT cancel-safe: a sign-in dropped mid-way can leave an orphaned router session; reads only.
pub(crate) async fn admit(base: &Base, allow_loopback: bool) -> TestResult<Admitted> {
    let admission = admission(&base.config, &base.url)?;
    let raw = Zeroizing::new(fs::read_to_string(&base.password_file)?);
    let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
    let connection = connect(
        base.url.parse()?,
        base.login.clone(),
        password,
        allow_loopback,
    )
    .await?;
    let serial = allowlisted(&connection.client, &base.allowed).await?;
    tracing::info!(serial_len = serial.len(), "router serial is allowlisted");
    let home = Home::new(base, &admission.outbound)?;
    Ok(Admitted { connection, home })
}

/// One finished `kcc` process.
#[derive(Debug)]
pub(crate) struct Run {
    /// Exit code.
    pub code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// A temporary kcc configuration, state directory and master key.
pub(crate) struct Home {
    /// Owner of every file.
    directory: TempDir,
}

impl Home {
    /// Writes the home: the admitted outbound policy and one `test_device` profile.
    fn new(base: &Base, outbound: &OutboundConfig) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let root = directory.path();
        master_key::write(&root.join("master.key"), [19_u8; 32])?;
        let networks = outbound
            .allowed_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        fs::write(
            root.join("kcc.toml"),
            format!(
                "[outbound]\nallowed_networks = {}\nallowed_suffixes = {}\nallow_loopback = {}\nargon2_max_iterations = {}\n\n[state]\ndir = {}\n\n[[routers]]\nname = \"{ROUTER}\"\nurl = {:?}\nlogin = {:?}\npassword_file = {}\ntest_device = true\n",
                serde_json::to_string(&networks)?,
                serde_json::to_string(&outbound.allowed_suffixes)?,
                outbound.allow_loopback,
                outbound.argon2_max_iterations,
                toml_text::path(&root.join("state")),
                base.url,
                base.login,
                toml_text::path(&base.password_file),
            ),
        )?;
        Ok(Self { directory })
    }

    /// Runs `kcc --config <home> --json --router <id> --confirm-destructive <id> <args>`.
    pub(crate) fn kcc(&self, args: &[&str]) -> TestResult<Run> {
        let root = self.directory.path();
        let home = root.join("home");
        let child = spawning::spawn(
            spawning::command(env!("CARGO_BIN_EXE_kcc"))
                .arg("--config")
                .arg(root.join("kcc.toml"))
                .args([
                    "--json",
                    "--router",
                    ROUTER,
                    "--confirm-destructive",
                    ROUTER,
                ])
                .args(args)
                .env_clear()
                // Windows sockets fail to load their provider without SystemRoot.
                .envs(env::var_os("SystemRoot").map(|value| ("SystemRoot", value)))
                .env("PATH", env::var_os("PATH").unwrap_or_default())
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_STATE_HOME", home.join("state"))
                .env("LOCALAPPDATA", home.join("state"))
                .env("APPDATA", home.join("config"))
                .env(MASTER_KEY_FILE_ENV, root.join("master.key"))
                .env("USER", "tester")
                .env("LANG", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        finish(child)
    }

    /// Runs [`Self::kcc`], requires exit 0 and returns the JSON document.
    pub(crate) fn json(&self, args: &[&str]) -> TestResult<Value> {
        let run = self.kcc(args)?;
        if run.code != 0_i32 {
            return Err(format!(
                "kcc {} exited {}: {}",
                args.get(..2).unwrap_or(args).join(" "),
                run.code,
                run.stderr.trim()
            )
            .into());
        }
        Ok(serde_json::from_str(&run.stdout)?)
    }

    /// Keeps the home on disk and returns its path.
    pub(crate) fn keep(self) -> PathBuf {
        self.directory.keep()
    }
}

/// Waits for `child` with the deadline and collects its output.
fn finish(mut child: Child) -> TestResult<Run> {
    let mut stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let mut stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out = thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).map(|_read| text)
    });
    let err = thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).map(|_read| text)
    });
    let Some(status) = child.wait_timeout(PROCESS_TIMEOUT)? else {
        child.kill()?;
        let _reaped = child.wait()?;
        return Err("kcc did not exit before the deadline".into());
    };
    Ok(Run {
        code: status.code().ok_or("kcc was killed by a signal")?,
        stdout: out.join().map_err(|_panic| "stdout reader panicked")??,
        stderr: err.join().map_err(|_panic| "stderr reader panicked")??,
    })
}
