//! Main listener restarts over TLS: the same address restart after restart, and a
//! certificate replaced between the build and the serve.

extern crate alloc;

use alloc::sync::Arc;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use kcc_app::{mcp_settings::ListenerKind, settings::mcp_schema::Endpoint};
use kcc_testkit::toml_text::path;
use rcgen::{CertificateParams, KeyPair};
use tokio::task::spawn_blocking;

use super::{
    super::{
        SHORT, TestResult, endpoint,
        fixture::{Fixture, Setup},
        hook,
    },
    generation,
};
use crate::server_listeners::{Restarted, RevertReason, health::Probe, supervisor::Stage};

/// How many restarts the same-address test runs.
const RESTARTS: u64 = 10;

/// A self-signed `localhost` certificate and its key, written to `directory`.
///
/// Files `<name>-cert.pem` and the owner-only `<name>-key.pem`; returns both paths and the
/// certificate's DER.
fn identity(directory: &Path, name: &str) -> TestResult<(PathBuf, PathBuf, Vec<u8>)> {
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
    let cert_file = directory.join(format!("{name}-cert.pem"));
    fs::write(&cert_file, cert.pem())?;
    let key_file = kcc_testkit::write_secret_file(
        directory,
        &format!("{name}-key.pem"),
        &key.serialize_pem(),
    )?;
    Ok((cert_file, key_file, cert.der().to_vec()))
}

/// The `[server]` lines serving TLS with `cert` and `key`.
fn tls(cert: &Path, key: &Path) -> String {
    format!(
        "tls_cert_path = {}\ntls_key_path = {}",
        path(cert),
        path(key)
    )
}

/// Todo 26: TLS main restarts that keep their address are applied every time.
///
/// The kit releases a stopped TLS listener's socket on its own task; the next generation
/// binds only once the address is free again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_main_restarts_on_the_same_address_are_applied() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (cert, key, _der) = identity(files.path(), "server")?;
    let fixture = Fixture::start(Setup {
        server: tls(&cert, &key),
        ..Setup::default()
    })
    .await?;
    let address = fixture.main()?;

    for round in 1..=RESTARTS {
        let value = if round.is_multiple_of(2) {
            Endpoint::Main
        } else {
            Endpoint::Both
        };
        let restarted = fixture
            .supervisor
            .restart(fixture.plan(&endpoint(value))?)
            .await?;

        assert!(
            matches!(restarted, Restarted::Applied),
            "restart {round}: {restarted:?}"
        );
        assert_eq!(fixture.main()?, address);
        assert_eq!(generation(&fixture)?, round.saturating_add(1));
    }
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a certificate replaced between the build and the serve fails the health check.
///
/// The check trusts exactly the certificate the new generation was built with: the
/// restart reverts and the previous generation serves again on its address (with the
/// files now on disk).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_replaced_before_the_serve_fails_the_health_check() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (cert, key, _built) = identity(files.path(), "server")?;
    let (other_cert, other_key, other) = identity(files.path(), "other")?;
    let replaced = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&replaced);
    let (served_cert, served_key) = (cert.clone(), key.clone());
    let fixture = Fixture::start(Setup {
        server: tls(&cert, &key),
        windows: Some(SHORT),
        hook: hook(move |stage| {
            if stage == Stage::Stopped {
                let swapped = fs::rename(&other_cert, &served_cert)
                    .and_then(|()| fs::rename(&other_key, &served_key));
                if let Ok(mut done) = slot.lock() {
                    *done = Some(swapped);
                }
            }
            async {}
        }),
        ..Setup::default()
    })
    .await?;
    let address = fixture.main()?;

    let restarted = fixture
        .supervisor
        .restart(fixture.plan(&endpoint(Endpoint::Both))?)
        .await?;

    assert!(
        matches!(
            restarted,
            Restarted::Reverted(RevertReason::Health {
                listener: ListenerKind::Main,
                reason: _,
            })
        ),
        "{restarted:?}"
    );
    assert!(
        replaced
            .lock()
            .map_err(|_poisoned| "poisoned")?
            .as_ref()
            .is_some_and(Result::is_ok),
        "the test replaced the certificate"
    );
    assert_eq!(fixture.main()?, address);
    assert_eq!(generation(&fixture)?, 3);
    spawn_blocking(move || Probe::new(Some(other), None).check(address, SHORT.health)).await??;
    assert_eq!(fixture.revision()?, 0);
    fixture.stop().await??;
    Ok(())
}
