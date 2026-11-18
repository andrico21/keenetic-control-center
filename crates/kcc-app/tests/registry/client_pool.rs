//! One router's slow client construction does not hold up the other routers (unix).

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{fs::OpenOptions, io::Write as _, process::Command as ChildCommand};

use kcc_app::{persist::StateStore, registry::RouterRegistry, settings::Config};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD,
    auth_fixture::{self, Options as Fixture},
};
use tempfile::TempDir;
use tokio::{task::spawn_blocking, time::timeout};

/// Bound on the unblocked router's client construction.
const CONNECT: Duration = Duration::from_secs(20);

/// SEC2-09: while the `slow` router's credential read is blocked (its password file is a
/// FIFO nobody has written yet), `client("fast")` for another router still completes.
// NOT cancel-safe: owns the fixture and the FIFO writer until both clients are built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::disallowed_methods,
    reason = "creates a FIFO with mkfifo, which std has no safe call for"
)]
async fn a_blocked_credential_read_does_not_stall_other_routers() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle, _counts) = auth_fixture::spawn(Fixture::default()).await?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let fifo = directory.path().join("slow-password");
    assert!(
        ChildCommand::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()?
            .success(),
        "mkfifo failed"
    );
    let router = |name: &str, file: &std::path::Path| {
        format!(
            "[[routers]]\nname = \"{name}\"\nurl = \"http://{address}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\n",
            file.display().to_string()
        )
    };
    let config = Config::from_toml_str(&format!(
        "[outbound]\nallow_loopback = true\n\n{}\n{}",
        router("slow", &fifo),
        router("fast", &password)
    ))?;
    let registry = Arc::new(RouterRegistry::new(
        StateStore::open(&directory.path().join("state"))?,
        &config.routers,
        &config.outbound,
    )?);
    let shared = Arc::clone(&registry);
    let slow = tokio::spawn(async move { shared.client("slow").await.map(drop) });
    // Opening the write end returns once the slow client's read has opened the FIFO.
    let writer_path = fifo.clone();
    let mut writer =
        spawn_blocking(move || OpenOptions::new().write(true).open(writer_path)).await??;

    let fast = timeout(CONNECT, registry.client("fast")).await;

    spawn_blocking(move || writer.write_all(DEFAULT_PASSWORD.as_bytes())).await??;
    slow.await??;
    assert!(fast.is_ok(), "client(\"fast\") waited for the slow router");
    drop(fast??);
    handle.shutdown().await?;
    Ok(())
}
