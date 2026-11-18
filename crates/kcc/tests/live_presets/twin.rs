//! Hermetic twin of the live preset rehearsal: two fake routers, the same code path.

use core::error::Error;
use std::fs;

use kcc_rci::{ConfigKind, RciBody, RciPath};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, capture::connect, migration,
    model::Profile,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tempfile::TempDir;

use super::{Target, TestResult, rehearse};

/// An `[outbound]` table admitting the fakes on loopback.
///
/// The documentation network keeps the copied `allowed_networks` non-empty.
const LOOPBACK: &str =
    "[outbound]\nallow_loopback = true\nallowed_networks = [\"198.51.100.0/24\"]\n\n";

/// Two fake routers: `fake-a`'s saved configuration is the source file, `fake-b` the target.
struct Twin {
    /// Temporary files.
    _files: TempDir,
    /// The live contract pointed at `fake-b`.
    lab: Target,
    /// `fake-a`.
    source: Handle,
    /// `fake-b`.
    target: Handle,
}

/// Starts both fakes and writes a configuration whose `[outbound]` table is `outbound`.
// NOT cancel-safe: starts background routers and writes temporary files.
async fn twin(outbound: &str) -> Result<Twin, Box<dyn Error>> {
    let local = ([127, 0, 0, 1], 0).into();
    let (source_address, source) = FakeRouter::spawn().await?;
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let (target_address, target) = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(scenario)
        .serve(local)
        .await?;
    let files = TempDir::new()?;
    let password_file = kcc_testkit::write_secret_file(files.path(), "password", DEFAULT_PASSWORD)?;
    let seed = connect(
        format!("http://{source_address}").parse()?,
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
        true,
    )
    .await?;
    for line in [
        "dns-proxy tls upstream 1.1.1.1 853",
        "ip route 198.51.100.0 255.255.255.0 192.0.2.254",
        "system configuration save",
    ] {
        drop(seed.client.parse(line).await?);
    }
    let saved = seed.client.download_config(ConfigKind::Startup).await?;
    fs::write(files.path().join("source.txt"), saved.expose_secret())?;
    let url = format!("http://{target_address}");
    fs::write(
        files.path().join("kcc.toml"),
        format!(
            "{outbound}[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\ntest_device = true\n",
            password_file.display().to_string()
        ),
    )?;
    let lab = Target {
        url,
        login: DEFAULT_LOGIN.to_owned(),
        password_file,
        config: files.path().join("kcc.toml"),
        allowed: vec![fake_serial(&target_address.to_string()).await?],
        source: files.path().join("source.txt"),
    };
    Ok(Twin {
        _files: files,
        lab,
        source,
        target,
    })
}

/// The twin: capture, apply, verify and fail-safe rollback against `fake-b`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presets_rehearsal_runs_against_two_fake_routers() -> TestResult {
    let twin = twin(LOOPBACK).await?;
    let identification = twin.target.request_count();
    rehearse(&twin.lab, true).await?;
    assert!(
        twin.target.request_count() > identification,
        "target untouched"
    );
    assert!(
        twin.target
            .request_log()
            .iter()
            .any(|record| record.command() == Some("system configuration fail-safe rollback")),
        "the run did not roll back through the fail-safe"
    );
    twin.source.shutdown().await?;
    twin.target.shutdown().await?;
    Ok(())
}

/// T-02: the built `kcc` runs under the admitted `[outbound]` policy, not a test flag.
///
/// A configuration that refuses the target's address stops the apply before the target
/// receives any parser line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presets_rehearsal_follows_the_admitted_outbound_policy() -> TestResult {
    let twin = twin("").await?;
    let outcome = rehearse(&twin.lab, true).await;
    assert!(outcome.is_err(), "a refused target was rehearsed");
    let lines = twin
        .target
        .request_log()
        .iter()
        .filter_map(|record| record.command().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        Vec::<String>::new(),
        "the target received parser lines"
    );
    twin.source.shutdown().await?;
    twin.target.shutdown().await?;
    Ok(())
}

/// Reads a fake router's serial.
// cancel-safe: one read.
async fn fake_serial(address: &str) -> Result<String, Box<dyn Error>> {
    let connection = connect(
        format!("http://{address}").parse()?,
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
        .and_then(Value::as_str)
        .ok_or("fake router has no serial")?
        .to_owned())
}
