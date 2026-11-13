//! Hermetic proof that the rehearsal refuses unsafe targets before any write.
#![expect(clippy::panic_in_result_fn, reason = "refusal tests fail by asserting")]

use core::error::Error;
use std::{fs, path::Path};

use kcc_rci::{RciBody, RciPath};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, capture::connect};
use secrecy::SecretString;
use tempfile::TempDir;

use super::{LiveEnv, SourceInput, TestResult, guard::Refusal, rehearse};

/// One fake target with its kcc configuration and password file.
struct Target {
    /// Temporary files.
    directory: TempDir,
    /// Router origin.
    url: String,
    /// Router handle.
    handle: Handle,
}

/// Starts a fake target and writes a configuration whose profile has `test_device`.
// NOT cancel-safe: starts a background router and writes temporary files.
async fn target(test_device: bool) -> Result<Target, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle) = FakeRouter::spawn().await?;
    let url = format!("http://{address}");
    let password_file =
        kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    fs::write(
        directory.path().join("kcc.toml"),
        format!(
            "[outbound]\nallow_loopback = true\n\n[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = \"{}\"\ntest_device = {test_device}\n",
            password_file.display()
        ),
    )?;
    fs::write(
        directory.path().join("source.txt"),
        "! $$$ Version: 5.1.3\n",
    )?;
    Ok(Target {
        directory,
        url,
        handle,
    })
}

/// The live contract pointed at the fake target.
fn env(target: &Target, allowed: Vec<String>) -> LiveEnv {
    let root: &Path = target.directory.path();
    LiveEnv {
        url: target.url.clone(),
        login: DEFAULT_LOGIN.to_owned(),
        password_file: root.join("password"),
        config: root.join("kcc.toml"),
        allowed,
        source: SourceInput::File(root.join("source.txt")),
        commit: false,
    }
}

/// Requests other than reads and the login exchange.
fn writes(handle: &Handle) -> usize {
    handle
        .request_log()
        .iter()
        .filter(|record| record.method() != "GET" && record.path() != "/auth")
        .count()
}

/// Reads the fake router serial for the positive control.
// cancel-safe: one read.
async fn serial(url: &str) -> Result<String, Box<dyn Error>> {
    let connection = connect(
        url.parse()?,
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
        true,
    )
    .await?;
    let path = RciPath::from_segments(["show", "identification"])?;
    match connection.client.get(&path, &()).await? {
        RciBody::Json(response) => Ok(response
            .value
            .get("serial")
            .and_then(serde_json::Value::as_str)
            .ok_or("fake router has no serial")?
            .to_owned()),
        RciBody::Text(_) | _ => Err("expected JSON identification".into()),
    }
}

/// Asserts a refusal with zero router writes and an unchanged configuration.
fn assert_refused(outcome: TestResult, expected: Refusal, target: &Target, before: &str) {
    let refusal = outcome
        .err()
        .and_then(|error| error.downcast_ref::<Refusal>().copied());
    assert_eq!(refusal, Some(expected), "unexpected gate outcome");
    assert_eq!(
        writes(&target.handle),
        0,
        "a refused target received a write"
    );
    assert_eq!(
        target.handle.running_config_text(),
        before,
        "target changed"
    );
}

/// A profile without `test_device = true` is refused before the router is contacted.
#[tokio::test]
async fn profile_without_test_device_is_refused_before_contact() -> TestResult {
    let target = target(false).await?;
    let before = target.handle.running_config_text();
    let allowed = vec![serial(&target.url).await?];
    let contacts = target.handle.request_count();
    let outcome = rehearse(env(&target, allowed), true).await;
    assert_refused(outcome, Refusal::NotTestDevice, &target, &before);
    assert_eq!(
        target.handle.request_count(),
        contacts,
        "gate contacted the router"
    );
    target.handle.shutdown().await?;
    Ok(())
}

/// A test device whose serial is not allowlisted is refused after one read and no write.
#[tokio::test]
async fn unlisted_serial_is_refused_before_any_write() -> TestResult {
    let target = target(true).await?;
    let before = target.handle.running_config_text();
    let outcome = rehearse(env(&target, vec!["S0000000000NOT".to_owned()]), true).await;
    assert_refused(outcome, Refusal::SerialNotAllowed, &target, &before);
    target.handle.shutdown().await?;
    Ok(())
}
