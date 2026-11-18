//! Live read-only smoke test: capability detection plus every captured path.
//!
//! `#[ignore]`d; run with `cargo test -p kcc --test live_smoke -- --ignored`. Needs
//! `KCC_LIVE_URL`, `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE`, `KCC_LIVE_ALLOW_SERIAL` and
//! `KCC_LIVE_TARGET_CONFIG` (a kcc configuration whose `[[routers]]` entry for `KCC_LIVE_URL`
//! has `test_device = true`); when one is missing the test logs `live-skip:<reason>` and
//! returns `Ok(())`. The profile is checked before the router is contacted, and the router
//! serial is checked against `KCC_LIVE_ALLOW_SERIAL` before any other resource is read.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

#[path = "support/live_gate.rs"]
mod live_gate;

use core::error::Error;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use kcc_rci::{RciBody, RciError, RciPath, RouterUrl, capabilities::RouterInfo};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
    capture::{Captured, connect, read_all},
    live_matrix::{self, Outcome, Run, Suite},
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use tempfile::TempDir;
use zeroize::Zeroizing;

use self::live_gate::{Refusal, admission, allowlisted};

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error>>;

/// The firmware matrix in the workspace evidence directory.
fn matrix_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.omo/evidence/task-51-keenetic-control-center.json")
}

/// The live environment contract.
struct LiveEnv {
    /// Router origin.
    url: String,
    /// Router account.
    login: String,
    /// Password file path.
    password_file: PathBuf,
    /// kcc configuration holding the router's `test_device = true` profile.
    config: PathBuf,
    /// Allowed serials.
    allowed: Vec<String>,
}

/// Reads the environment, or names the first missing variable.
fn live_env() -> Result<LiveEnv, &'static str> {
    let read = |name: &'static str, reason: &'static str| {
        env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or(reason)
    };
    let url = read("KCC_LIVE_URL", "kcc_live_url-unset")?;
    let login = read("KCC_LIVE_LOGIN", "kcc_live_login-unset")?;
    let password_file = read("KCC_LIVE_PASSWORD_FILE", "kcc_live_password_file-unset")?;
    let config = read("KCC_LIVE_TARGET_CONFIG", "kcc_live_target_config-unset")?;
    let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    Ok(LiveEnv {
        url,
        login,
        password_file: PathBuf::from(password_file),
        config: PathBuf::from(config),
        allowed,
    })
}

/// Logs every captured item and names the ones the router answered with an RCI error.
fn failures(captured: &[Captured]) -> Vec<String> {
    for (item, result) in captured {
        match result {
            Ok(_) => tracing::info!(item = item.name, "read"),
            Err(RciError::NotFound) => tracing::info!(item = item.name, "absent"),
            Err(error) => tracing::warn!(item = item.name, error = ?error, "failed"),
        }
    }
    captured
        .iter()
        .filter(|(_item, result)| {
            matches!(
                result,
                Err(RciError::Rci {
                    pointer: _,
                    code: _,
                    ident: _,
                    message: _,
                })
            )
        })
        .map(|(item, _result)| item.name.clone())
        .collect()
}

/// Reads the router through the gate and returns its matrix identity.
///
/// # Errors
/// Returns refusals, transport failures, an empty capture and RCI errors on captured paths.
// NOT cancel-safe: a sign-in dropped mid-way can leave an orphaned router session; every
// request is a read.
async fn smoke(live: LiveEnv, allow_loopback: bool) -> Result<Run, Box<dyn Error>> {
    let LiveEnv {
        url,
        login,
        password_file,
        config,
        allowed,
    } = live;
    drop(admission(&config, &url)?);
    let raw = Zeroizing::new(fs::read_to_string(&password_file)?);
    let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
    let router = url.parse::<RouterUrl>()?;
    let connection = connect(router.clone(), login, password, allow_loopback).await?;
    let serial = allowlisted(&connection.client, &allowed).await?;
    tracing::info!(serial_len = serial.len(), "router serial is allowlisted");
    let info = RouterInfo::detect(&connection.session, &router).await?;
    tracing::info!(
        hw_id = info.hw_id().unwrap_or("unknown"),
        title = info.version.title.as_deref().unwrap_or("unknown"),
        components = info.components.len(),
        "capabilities detected"
    );
    let captured = read_all(&connection).await;
    if captured.is_empty() {
        return Err("no captured path was read".into());
    }
    let failed = failures(&captured);
    if !failed.is_empty() {
        return Err(format!("RCI errors on: {failed:?}").into());
    }
    Ok(Run::observed(&serial, &info))
}

#[tokio::test]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_read_only_smoke() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    let live = match live_env() {
        Ok(live) => live,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            live_matrix::record_skip(&matrix_path(), "live_smoke", reason)?;
            return Ok(());
        }
    };
    let run = smoke(live, false).await?;
    live_matrix::record(
        &matrix_path(),
        &run,
        Suite::new("live_smoke", Outcome::Pass, ""),
    )?;
    Ok(())
}

/// A 5.1 KN-1811 fake router with a kcc configuration naming it.
struct Lab {
    /// Temporary files.
    directory: TempDir,
    /// Router origin.
    url: String,
    /// Router handle.
    handle: Handle,
}

/// Starts the fake and writes a profile with `test_device`; loopback is admitted by the
/// configuration's own `[outbound]` table.
// NOT cancel-safe: starts a background router and writes temporary files.
async fn lab(test_device: bool) -> Result<Lab, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle) = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_1)?)
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let url = format!("http://{address}");
    let password_file =
        kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    fs::write(
        directory.path().join("kcc.toml"),
        format!(
            "[outbound]\nallow_loopback = true\nallowed_networks = [\"198.51.100.0/24\"]\n\n[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\ntest_device = {test_device}\n",
            password_file.display().to_string()
        ),
    )?;
    Ok(Lab {
        directory,
        url,
        handle,
    })
}

/// Reads the fake router serial for the positive control.
// cancel-safe: one read.
async fn fake_serial(url: &str) -> Result<String, Box<dyn Error>> {
    let connection = connect(
        url.parse()?,
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
        true,
    )
    .await?;
    let path = RciPath::from_segments(["show", "identification"])?;
    let RciBody::Json(response) = connection.client.get(&path, &()).await? else {
        return Err("expected JSON identification".into());
    };
    Ok(response
        .value
        .get("serial")
        .and_then(serde_json::Value::as_str)
        .ok_or("fake router has no serial")?
        .to_owned())
}

/// The live contract pointed at the lab.
fn env(lab: &Lab, allowed: Vec<String>) -> LiveEnv {
    let root: &Path = lab.directory.path();
    LiveEnv {
        url: lab.url.clone(),
        login: DEFAULT_LOGIN.to_owned(),
        password_file: root.join("password"),
        config: root.join("kcc.toml"),
        allowed,
    }
}

/// T-08, F-31: the read-only smoke refuses a profile without `test_device = true`.
///
/// The refusal comes before the router receives a single request.
#[tokio::test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by asserting")]
async fn read_only_smoke_refuses_a_profile_without_test_device_before_contact() -> TestResult {
    let lab = lab(false).await?;
    let outcome = smoke(env(&lab, vec!["S0000000000001".to_owned()]), true).await;
    let refusal = outcome
        .err()
        .and_then(|error| error.downcast_ref::<Refusal>().copied());
    assert_eq!(refusal, Some(Refusal::NotTestDevice));
    assert_eq!(
        lab.handle.request_count(),
        0,
        "the gate contacted the router"
    );
    lab.handle.shutdown().await?;
    Ok(())
}

/// The smoke reads every captured path of an admitted, allowlisted test device.
#[tokio::test]
async fn smoke_runs_against_the_fake_router() -> TestResult {
    let lab = lab(true).await?;
    let serial = fake_serial(&lab.url).await?;
    drop(smoke(env(&lab, vec![serial]), true).await?);
    lab.handle.shutdown().await?;
    Ok(())
}
