//! Live per-domain campaign plus hermetic twins that run the same code against the fake router.
//!
//! The live tests are `#[ignore]`d; run them with
//! `cargo test -p kcc --test live_domains -- --ignored`. They need `KCC_LIVE_URL`,
//! `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE` and `KCC_LIVE_ALLOW_SERIAL`; a missing variable
//! logs `live-skip:<reason>` and returns `Ok(())`. Every read follows the serial check. Writes
//! additionally need `KCC_LIVE_ALLOW_WRITE=1` and `KCC_LIVE_TARGET_CONFIG`, a kcc
//! configuration whose `[[routers]]` entry for `KCC_LIVE_URL` has `test_device = true`; the
//! profile is checked before the router is contacted. Each reversible write is verified by a
//! fresh read and reverted; the suite snapshots the running configuration, arms the fail-safe
//! timer for 900 s, compares the normalized running configuration at the end and disarms the
//! timer only on an exact match. It never saves.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

extern crate alloc;

#[path = "live_domains/campaign.rs"]
mod campaign;
#[path = "live_domains/gate.rs"]
mod gate;
#[path = "live_domains/harness.rs"]
mod harness;
#[path = "live_domains/matrix.rs"]
mod matrix;
#[path = "live_domains/reads.rs"]
mod reads;
#[path = "live_domains/refusal.rs"]
mod refusal;
#[path = "live_domains/safety.rs"]
mod safety;
#[path = "live_domains/writes.rs"]
mod writes;
#[path = "live_domains/writes_net.rs"]
mod writes_net;

use core::error::Error;
use std::{env, fs, io, path::PathBuf};

use kcc_testkit::live_matrix::{Outcome, Run, Suite};
use secrecy::SecretString;
use zeroize::Zeroizing;

use self::campaign::{Options, WriteMode};

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Suite name of the per-domain campaign in the firmware matrix.
const SUITE: &str = "live_domains";

/// The live environment contract of this suite.
struct LiveEnv {
    /// Router origin.
    url: String,
    /// Router account.
    login: String,
    /// Password file.
    password_file: PathBuf,
    /// Allowed serials.
    allowed: Vec<String>,
    /// Write gate.
    write: WriteMode,
}

/// Reads one non-empty variable or names it in the skip reason.
fn read(name: &'static str, reason: &'static str) -> Result<String, &'static str> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(reason)
}

/// Reads the environment, or names the first missing variable.
fn live_env() -> Result<LiveEnv, &'static str> {
    let url = read("KCC_LIVE_URL", "kcc_live_url-unset")?;
    let login = read("KCC_LIVE_LOGIN", "kcc_live_login-unset")?;
    let password_file = read("KCC_LIVE_PASSWORD_FILE", "kcc_live_password_file-unset")?;
    let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    let write = if read("KCC_LIVE_ALLOW_WRITE", "").as_deref() == Ok("1") {
        match read("KCC_LIVE_TARGET_CONFIG", "") {
            Ok(config) => WriteMode::Requested(PathBuf::from(config)),
            Err(_unset) => {
                tracing::warn!("live-skip:kcc_live_target_config-unset (writes skipped)");
                WriteMode::ReadOnly
            }
        }
    } else {
        tracing::warn!("live-skip:kcc_live_allow_write-not-1 (writes skipped)");
        WriteMode::ReadOnly
    };
    Ok(LiveEnv {
        url,
        login,
        password_file: PathBuf::from(password_file),
        allowed,
        write,
    })
}

/// Builds campaign options from the live contract.
fn options(live: LiveEnv) -> Result<Options, Box<dyn Error>> {
    let raw = Zeroizing::new(fs::read_to_string(&live.password_file)?);
    Ok(Options {
        url: live.url,
        login: live.login,
        password: SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned()),
        password_file: live.password_file,
        allowed: live.allowed,
        write: live.write,
        allow_loopback: false,
        leave_unreverted: None,
    })
}

#[tokio::test]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_domains_campaign() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    let live = match live_env() {
        Ok(live) => live,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            return matrix::skip(SUITE, reason);
        }
    };
    match campaign::run(options(live)?).await {
        Ok(report) => {
            report.log();
            matrix::record(&report.run, Suite::new(SUITE, Outcome::Pass, ""))
        }
        Err(error) => {
            matrix::record(
                &Run::unavailable(),
                Suite::new(SUITE, Outcome::Fail, &error.to_string()),
            )?;
            Err(error)
        }
    }
}

#[tokio::test]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_auth_matrix() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    match live_env() {
        Ok(live) => matrix::auth(options(live)?).await,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            matrix::skip(matrix::AUTH_SUITE, reason)
        }
    }
}

#[tokio::test]
#[ignore = "live router: records the live campaign matrix"]
async fn live_campaign_matrix() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    matrix::campaign()
}
