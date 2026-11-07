//! Hermetic twin: the live campaign's exact code path against the 5.1 KN-1811 fake router.
#![expect(clippy::panic_in_result_fn, reason = "harness tests fail by asserting")]

use core::error::Error;
use std::fs;

use kcc_domain::DomainId;
use kcc_rci::{RciBody, RciPath};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
    capture::connect,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use tempfile::TempDir;

use super::{
    TestResult,
    campaign::{self, Options, WriteMode},
    safety::{ARM, DISARM, SnapshotMismatch},
    writes::WriteResult,
};

/// One fake router with its kcc configuration and password file.
pub(crate) struct Lab {
    /// Temporary files.
    pub directory: TempDir,
    /// Router origin.
    pub url: String,
    /// Router handle.
    pub handle: Handle,
    /// The fake router's serial.
    pub serial: String,
}

impl Lab {
    /// Starts a 5.1 KN-1811 fake and writes a configuration whose profile has `test_device`.
    // NOT cancel-safe: starts a background router and writes temporary files.
    pub(crate) async fn start(test_device: bool) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let profile = Profile::new(Model::Kn1811, Firmware::V5_1)?;
        let (address, handle) = FakeRouter::builder(profile)
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let url = format!("http://{address}");
        let password_file = directory.path().join("password");
        fs::write(&password_file, DEFAULT_PASSWORD)?;
        fs::write(
            directory.path().join("kcc.toml"),
            format!(
                "[outbound]\nallow_loopback = true\n\n[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = \"{}\"\ntest_device = {test_device}\n",
                password_file.display()
            ),
        )?;
        let serial = serial(&url).await?;
        Ok(Self {
            directory,
            url,
            handle,
            serial,
        })
    }

    /// Campaign options against this lab, as the live entry point builds them.
    pub(crate) fn options(&self, write: bool, allowed: Vec<String>) -> Options {
        Options {
            url: self.url.clone(),
            login: DEFAULT_LOGIN.to_owned(),
            password: SecretString::from(DEFAULT_PASSWORD.to_owned()),
            password_file: self.directory.path().join("password"),
            allowed,
            write: if write {
                WriteMode::Requested(self.directory.path().join("kcc.toml"))
            } else {
                WriteMode::ReadOnly
            },
            allow_loopback: true,
            leave_unreverted: None,
        }
    }

    /// Parser lines the router received.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(ToOwned::to_owned))
            .collect()
    }
}

/// Reads the fake router serial.
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

/// The full read/write/revert/compare flow passes and leaves the router byte-identical.
#[tokio::test]
async fn live_domains_harness_runs_against_the_fake_router() -> TestResult {
    drop(tracing_subscriber::fmt().with_test_writer().try_init());
    let lab = Lab::start(true).await?;
    let running = lab.handle.running_config_text();
    let startup = lab.handle.startup_config_text();
    let report = campaign::run(lab.options(true, vec![lab.serial.clone()])).await?;
    report.log();
    let domains = kcc_domain::registry().len();
    assert_eq!(report.writes.len(), domains, "one write outcome per domain");
    let reverted = report
        .writes
        .iter()
        .filter(|write| write.result == WriteResult::Reverted)
        .map(|write| write.domain)
        .collect::<Vec<_>>();
    for expected in [
        DomainId::Interfaces,
        DomainId::Routing,
        DomainId::Nat,
        DomainId::Schedules,
        DomainId::Clients,
    ] {
        assert!(
            reverted.contains(&expected),
            "{expected:?} was not reverted"
        );
    }
    assert!(!report.reads.is_empty(), "the catalog offered no read");
    assert_eq!(lab.handle.running_config_text(), running, "running changed");
    assert_eq!(lab.handle.startup_config_text(), startup, "the suite saved");
    let commands = lab.commands();
    assert!(
        commands.iter().any(|line| line == ARM),
        "fail-safe never armed"
    );
    assert_eq!(commands.last().map(String::as_str), Some(DISARM));
    assert!(
        commands
            .iter()
            .all(|line| !line.contains("configuration save")),
        "the suite saved"
    );
    lab.handle.shutdown().await?;
    Ok(())
}

/// Mutation check of the safety net: one unreverted write fails the suite and keeps the
/// fail-safe timer armed so the router rolls itself back.
#[tokio::test]
async fn unreverted_write_fails_the_safety_net_and_keeps_the_timer_armed() -> TestResult {
    let lab = Lab::start(true).await?;
    let mut options = lab.options(true, vec![lab.serial.clone()]);
    options.leave_unreverted = Some(DomainId::Schedules);
    let outcome = campaign::run(options).await;
    let mismatch = outcome
        .err()
        .and_then(|error| error.downcast_ref::<SnapshotMismatch>().copied());
    assert!(
        mismatch.is_some(),
        "an unreverted write passed the safety net"
    );
    let commands = lab.commands();
    assert!(
        commands.iter().any(|line| line == ARM),
        "fail-safe never armed"
    );
    assert!(
        commands.iter().all(|line| line != DISARM),
        "the timer was disarmed despite a mismatch"
    );
    lab.handle.shutdown().await?;
    Ok(())
}
