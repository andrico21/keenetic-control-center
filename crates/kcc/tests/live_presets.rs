//! Live preset rehearsal plus its hermetic twin against two fake routers.
//!
//! The live test is `#[ignore]`d; run it with
//! `cargo test -p kcc --test live_presets -- --ignored`. It needs `KCC_LIVE_TARGET_URL`,
//! `KCC_LIVE_TARGET_LOGIN`, `KCC_LIVE_TARGET_PASSWORD_FILE`, `KCC_LIVE_TARGET_CONFIG` (its
//! `[[routers]]` entry for the target URL has `test_device = true`), `KCC_LIVE_ALLOW_WRITE=1`,
//! `KCC_LIVE_ALLOW_SERIAL`, `KCC_LIVE_SOURCE_FILE`, and `KCC_LIVE_ALLOW_REBOOT=1` because the
//! fail-safe rollback reboots the target into its startup configuration. A missing variable
//! logs `live-skip:<reason>` and returns `Ok(())`. The built `kcc` captures `dns-secure` and
//! `static-routes` from the source file, applies them in Merge mode under the fail-safe timer,
//! verifies, rolls back, and the test asserts the pre-apply running configuration returned.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and assert router state"
)]

#[path = "live_presets/twin.rs"]
mod twin;

use core::{error::Error, time::Duration};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use kcc_app::{secrets::MASTER_KEY_FILE_ENV, settings::Config};
use kcc_config::config_text::normalize;
use kcc_rci::{ConfigKind, RciBody, RciClient, RciPath};
use kcc_testkit::{
    capture::{connect, verify_serial},
    live_matrix,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;
use zeroize::Zeroizing;

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Suite name in the firmware matrix.
const SUITE: &str = "live_presets";

/// Longest time one `kcc` process may run (a rollback waits for the reboot).
const PROCESS_TIMEOUT: Duration = Duration::from_mins(15);

/// The target, its gate and the saved source configuration.
struct Target {
    /// Target origin.
    url: String,
    /// Target account.
    login: String,
    /// Target password file.
    password_file: PathBuf,
    /// kcc configuration naming the target profile.
    config: PathBuf,
    /// Allowed serials.
    allowed: Vec<String>,
    /// Saved source configuration.
    source: PathBuf,
}

/// Reads the environment, or names the first missing variable.
fn live_env() -> Result<Target, &'static str> {
    let read = |name: &'static str, reason: &'static str| {
        env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or(reason)
    };
    let url = read("KCC_LIVE_TARGET_URL", "kcc_live_target_url-unset")?;
    let login = read("KCC_LIVE_TARGET_LOGIN", "kcc_live_target_login-unset")?;
    let password = read(
        "KCC_LIVE_TARGET_PASSWORD_FILE",
        "kcc_live_target_password_file-unset",
    )?;
    let config = read("KCC_LIVE_TARGET_CONFIG", "kcc_live_target_config-unset")?;
    if read("KCC_LIVE_ALLOW_WRITE", "kcc_live_allow_write-unset")? != "1" {
        return Err("kcc_live_allow_write-not-1");
    }
    if read("KCC_LIVE_ALLOW_REBOOT", "kcc_live_allow_reboot-unset")? != "1" {
        return Err("kcc_live_allow_reboot-not-1");
    }
    let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    let source = read("KCC_LIVE_SOURCE_FILE", "kcc_live_source_file-unset")?;
    Ok(Target {
        url,
        login,
        password_file: PathBuf::from(password),
        config: PathBuf::from(config),
        allowed,
        source: PathBuf::from(source),
    })
}

/// Connects after the profile check and the serial check; nothing is written.
// cancel-safe: reads only.
async fn admit(target: &Target, allow_loopback: bool) -> Result<RciClient, Box<dyn Error>> {
    let wanted = target.url.trim_end_matches('/');
    let profile = Config::load(&target.config)?
        .routers
        .into_iter()
        .find(|profile| profile.url.as_str().trim_end_matches('/') == wanted)
        .ok_or("target URL has no router profile")?;
    if !profile.test_device {
        return Err("target profile is not marked test_device = true".into());
    }
    let raw = Zeroizing::new(fs::read_to_string(&target.password_file)?);
    let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
    let connection = connect(
        target.url.parse()?,
        target.login.clone(),
        password,
        allow_loopback,
    )
    .await?;
    drop(verify_serial(&connection.client, &target.allowed).await?);
    Ok(connection.client)
}

/// The normalized running configuration, refusing a target with unsaved changes (a fail-safe
/// rollback restores startup, which then differs from running).
// cancel-safe: reads only.
async fn clean_running(client: &RciClient) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let path = RciPath::from_segments(["show", "last-change"])?;
    let RciBody::Json(change) = client.show(&path, &()).await? else {
        return Err("show last-change is not JSON".into());
    };
    if change.value.get("unsaved").and_then(Value::as_bool) != Some(false) {
        return Err("target has unsaved changes; save or roll them back first".into());
    }
    let bytes = client.download_config(ConfigKind::Running).await?;
    let text = Zeroizing::new(String::from_utf8(bytes.expose_secret().to_vec())?);
    Ok(Zeroizing::new(normalize(&text)?))
}

/// Runs the built `kcc` with a hermetic home, state and master key.
fn kcc(home: &Path, args: &[&str]) -> Result<(i32, String), Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kcc"))
        .arg("--config")
        .arg(home.join("kcc.toml"))
        .args(args)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.join("home"))
        .env("XDG_CONFIG_HOME", home.join("home/config"))
        .env("XDG_STATE_HOME", home.join("home/state"))
        .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
        .env("USER", "tester")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let Some(status) = child.wait_timeout(PROCESS_TIMEOUT)? else {
        child.kill()?;
        return Err("kcc did not exit before the deadline".into());
    };
    let output = child.wait_with_output()?;
    Ok((
        status.code().ok_or("kcc was killed by a signal")?,
        String::from_utf8(output.stdout)?,
    ))
}

/// Writes the hermetic kcc configuration registering only the admitted target.
fn hermetic(target: &Target, allow_loopback: bool) -> Result<TempDir, Box<dyn Error>> {
    let home = TempDir::new()?;
    let key = home.path().join("master.key");
    fs::write(&key, [51_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(
        home.path().join("kcc.toml"),
        format!(
            "[outbound]\nallow_loopback = {allow_loopback}\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"target\"\nurl = {:?}\nlogin = {:?}\npassword_file = {:?}\ntest_device = true\n",
            home.path().join("state").display().to_string(),
            target.url,
            target.login,
            target.password_file.display().to_string(),
        ),
    )?;
    Ok(home)
}

/// Captures, applies in Merge mode, verifies, rolls back, and compares running configs.
// NOT cancel-safe: mutates the admitted test router under its fail-safe timer.
async fn rehearse(target: &Target, allow_loopback: bool) -> TestResult {
    let client = admit(target, allow_loopback).await?;
    let before = clean_running(&client).await?;
    drop(client);
    let home = hermetic(target, allow_loopback)?;
    let from = format!("file:{}", target.source.display());
    let groups = "dns-secure,static-routes";
    let capture = ["preset", "capture", "--from", &from, "--groups", groups];
    let (captured, _) = kcc(home.path(), &[&capture[..], &["--name", "live51"]].concat())?;
    assert_eq!(captured, 0_i32, "preset capture failed");
    let apply = [
        "--router", "target", "--json", "preset", "apply", "live51", "--mode", "merge", "--yes",
        "--finish", "rollback",
    ];
    let (applied, stdout) = kcc(home.path(), &apply)?;
    assert_eq!(applied, 0_i32, "preset apply failed: {stdout}");
    let result: Value = serde_json::from_str(&stdout)?;
    assert_eq!(result.get("verified"), Some(&Value::Bool(true)), "{result}");
    assert_eq!(
        result.get("finish").and_then(Value::as_str),
        Some("rollback"),
        "{result}"
    );
    let after = admit(target, allow_loopback).await?;
    let restored = clean_running(&after).await?;
    assert!(
        restored.as_str() == before.as_str(),
        "rollback left changes"
    );
    Ok(())
}

/// `.omo/evidence/task-51-keenetic-control-center.json` in the workspace.
fn matrix_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.omo/evidence/task-51-keenetic-control-center.json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_presets_rehearsal() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    match live_env() {
        Ok(target) => rehearse(&target, false).await,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            Ok(live_matrix::record_skip(&matrix_path(), SUITE, reason)?)
        }
    }
}
