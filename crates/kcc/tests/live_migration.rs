//! Live migration rehearsal plus hermetic proofs of its write gate.
//!
//! The rehearsal is `#[ignore]`d; run it with
//! `cargo test -p kcc --test live_migration -- --ignored`. It needs `KCC_LIVE_TARGET_URL`,
//! `KCC_LIVE_TARGET_LOGIN`, `KCC_LIVE_TARGET_PASSWORD_FILE`, `KCC_LIVE_TARGET_CONFIG` (a kcc
//! configuration whose `[[routers]]` entry for the target URL has `test_device = true`),
//! `KCC_LIVE_ALLOW_WRITE=1`, `KCC_LIVE_ALLOW_SERIAL`, and either `KCC_LIVE_SOURCE_FILE` (the
//! default) or `KCC_LIVE_SOURCE_URL`/`_LOGIN`/`_PASSWORD_FILE`. A missing variable logs
//! `live-skip:<reason>` and returns `Ok(())`. The target is rolled back unless
//! `KCC_LIVE_COMMIT=1`.

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

#[path = "live_migration/evidence.rs"]
mod evidence;
#[path = "live_migration/guard.rs"]
mod guard;
#[path = "support/live_gate.rs"]
mod live_gate;
#[path = "live_migration/probe.rs"]
mod probe;
#[path = "live_migration/probe_cleanup.rs"]
mod probe_cleanup;
#[path = "live_migration/refusal.rs"]
mod refusal;
#[path = "live_migration/rehearsal.rs"]
mod rehearsal;

use core::error::Error;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use kcc_testkit::{capture::connect_as, live_matrix::record_skip};
use secrecy::SecretString;
use zeroize::Zeroizing;

use self::{
    evidence::Evidence,
    guard::{Gate, admit},
    live_gate::allowlisted,
    rehearsal::{Rehearsal, SourceInput},
};

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error>>;

/// The live environment contract of the rehearsal.
struct LiveEnv {
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
    /// Migration source.
    source: SourceInput,
    /// Commit instead of rolling back.
    commit: bool,
}

/// Reads the environment, or names the first missing variable.
fn live_env() -> Result<LiveEnv, &'static str> {
    let read = |name: &'static str, reason: &'static str| {
        env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or(reason)
    };
    let url = read("KCC_LIVE_TARGET_URL", "kcc_live_target_url-unset")?;
    let login = read("KCC_LIVE_TARGET_LOGIN", "kcc_live_target_login-unset")?;
    let password_file = read(
        "KCC_LIVE_TARGET_PASSWORD_FILE",
        "kcc_live_target_password_file-unset",
    )?;
    let config = read("KCC_LIVE_TARGET_CONFIG", "kcc_live_target_config-unset")?;
    if read("KCC_LIVE_ALLOW_WRITE", "kcc_live_allow_write-unset")? != "1" {
        return Err("kcc_live_allow_write-not-1");
    }
    let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    let source = match read("KCC_LIVE_SOURCE_FILE", "") {
        Ok(file) => SourceInput::File(PathBuf::from(file)),
        Err(_unset) => SourceInput::Live {
            url: read("KCC_LIVE_SOURCE_URL", "kcc_live_source_file-and-url-unset")?,
            login: read("KCC_LIVE_SOURCE_LOGIN", "kcc_live_source_login-unset")?,
            password_file: PathBuf::from(read(
                "KCC_LIVE_SOURCE_PASSWORD_FILE",
                "kcc_live_source_password_file-unset",
            )?),
        },
    };
    Ok(LiveEnv {
        url,
        login,
        password_file: PathBuf::from(password_file),
        config: PathBuf::from(config),
        allowed,
        source,
        commit: env::var("KCC_LIVE_COMMIT").is_ok_and(|value| value == "1"),
    })
}

/// Reads a password file without its line ending.
fn read_password(path: &Path) -> Result<SecretString, Box<dyn Error>> {
    let raw = Zeroizing::new(fs::read_to_string(path)?);
    Ok(SecretString::from(
        raw.trim_end_matches(['\r', '\n']).to_owned(),
    ))
}

/// Admits the target through the write gate and a live source through the serial allowlist,
/// then rehearses; nothing writes before admission and the source is read only once listed.
// NOT cancel-safe: an admitted rehearsal mutates the test router under fail-safe protection.
async fn rehearse(live: LiveEnv, allow_loopback: bool) -> TestResult {
    let password = read_password(&live.password_file)?;
    let admitted = admit(Gate {
        config: &live.config,
        url: &live.url,
        login: &live.login,
        password: password.clone(),
        allowed: &live.allowed,
        allow_loopback,
    })
    .await?;
    if let SourceInput::Live {
        url,
        login,
        password_file,
    } = &live.source
    {
        let router = url.parse()?;
        let source_password = read_password(password_file)?;
        let source = connect_as(
            "migration-source",
            router,
            login.clone(),
            source_password,
            allow_loopback,
        )
        .await?;
        drop(allowlisted(&source.client, &live.allowed).await?);
    }
    let mut evidence = Evidence::open()?;
    rehearsal::run(
        Rehearsal {
            admitted,
            url: live.url,
            login: live.login,
            password_file: live.password_file,
            password,
            source: live.source,
            commit: live.commit,
        },
        &mut evidence,
    )
    .await
}

#[tokio::test]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_migration_rehearsal() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    match live_env() {
        Ok(live) => rehearse(live, false).await,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            let matrix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.omo/evidence/task-51-keenetic-control-center.json");
            Ok(record_skip(&matrix, "live_migration", reason)?)
        }
    }
}
