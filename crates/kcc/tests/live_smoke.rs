//! Live read-only smoke test: capability detection plus every captured path.
//!
//! `#[ignore]`d; run with `cargo test -p kcc --test live_smoke -- --ignored`. Needs
//! `KCC_LIVE_URL`, `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE` and `KCC_LIVE_ALLOW_SERIAL`;
//! when one is missing the test logs `live-skip:<reason>` and returns `Ok(())`. The router
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

use core::error::Error;
use std::{env, fs, io, path::PathBuf};

use kcc_rci::{RciError, RouterUrl, capabilities::RouterInfo};
use kcc_testkit::{
    capture::{connect, read_all, verify_serial},
    live_matrix::{self, Outcome, Run, Suite},
};
use secrecy::SecretString;
use zeroize::Zeroizing;

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
    password_file: String,
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
    let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    Ok(LiveEnv {
        url,
        login,
        password_file,
        allowed,
    })
}

#[tokio::test]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
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
    let raw = Zeroizing::new(fs::read_to_string(&live.password_file)?);
    let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
    let router = live.url.parse::<RouterUrl>()?;
    let connection = connect(router.clone(), live.login, password, false).await?;
    let serial = verify_serial(&connection.client, &live.allowed).await?;
    tracing::info!(serial_len = serial.len(), "router serial is allowlisted");
    let info = RouterInfo::detect(&connection.session, &router).await?;
    tracing::info!(
        hw_id = info.hw_id().unwrap_or("unknown"),
        title = info.version.title.as_deref().unwrap_or("unknown"),
        components = info.components.len(),
        "capabilities detected"
    );
    let captured = read_all(&connection).await;
    let mut failed = Vec::new();
    for (item, result) in &captured {
        match result {
            Ok(_) => tracing::info!(item = item.name, "read"),
            Err(RciError::NotFound) => tracing::info!(item = item.name, "absent"),
            Err(error) => {
                tracing::warn!(item = item.name, error = ?error, "failed");
                if matches!(
                    error,
                    RciError::Rci {
                        pointer: _,
                        code: _,
                        ident: _,
                        message: _,
                    }
                ) {
                    failed.push(item.name.clone());
                }
            }
        }
    }
    assert!(!captured.is_empty(), "every captured path was read");
    assert!(failed.is_empty(), "RCI errors on: {failed:?}");
    live_matrix::record(
        &matrix_path(),
        &Run::observed(&serial, &info),
        Suite::new("live_smoke", Outcome::Pass, ""),
    )?;
    Ok(())
}
