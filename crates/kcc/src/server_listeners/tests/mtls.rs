//! Client-certificate sign-in through the supervisor: restarts into `optional` and
//! `required`, and the health check's client-certificate rule against listeners that do or
//! do not enforce it.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    fs, io,
    io::{BufRead as _, BufReader, Write as _},
    net::TcpListener,
    path::Path,
    sync::Mutex,
    thread,
};

use kcc_app::{
    mcp_settings::{
        ListenerKind,
        client_ca::{mtls_ca_path, store_mtls_ca},
        document::McpOverrides,
    },
    settings::mcp_schema::MtlsMode,
};
use kcc_testkit::toml_text::path;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::task::spawn_blocking;

use super::{
    SHORT, TestResult,
    fixture::{Fixture, Setup, free_port},
    hook,
};
use crate::server_listeners::{
    ListenerError, Restarted, RevertReason, health::Probe, supervisor::Stage,
};

/// The window of the probes these tests run.
const WINDOW: Duration = Duration::from_secs(1);

/// A self-signed `localhost` certificate and its key in `directory`: the `[server]` lines
/// serving TLS with them, the certificate's DER and the key's PKCS#8 DER.
fn identity(directory: &Path) -> TestResult<(String, Vec<u8>, Vec<u8>)> {
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
    let cert_file = directory.join("server-cert.pem");
    fs::write(&cert_file, cert.pem())?;
    let key_file =
        kcc_testkit::write_secret_file(directory, "server-key.pem", &key.serialize_pem())?;
    let lines = format!(
        "tls_cert_path = {}\ntls_key_path = {}",
        path(&cert_file),
        path(&key_file)
    );
    Ok((lines, cert.der().to_vec(), key.serialize_der()))
}

/// A client CA certificate as PEM and DER.
fn client_ca() -> TestResult<(String, Vec<u8>)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&KeyPair::generate()?)?;
    Ok((cert.pem(), cert.der().to_vec()))
}

/// Whether the health check of `der`'s listener at `address` passes when it expects `mtls`.
async fn passes(address: SocketAddr, der: &[u8], mtls: MtlsMode) -> TestResult<bool> {
    let probe = Probe::new(Some(der.to_vec()), None).with_mtls(mtls);
    Ok(spawn_blocking(move || probe.check(address, WINDOW))
        .await?
        .is_ok())
}

/// Todo 28: restarts into client-certificate sign-in pass the health check.
///
/// A supervisor restart into `mtls = "required"` on the dedicated listener and into
/// `"optional"` on main is applied: the restarted listeners ask for a client certificate,
/// the dedicated one refuses a client without one, main answers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarts_into_client_certificate_sign_in_pass_the_health_check() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (server, der, _key) = identity(files.path())?;
    let fixture = Fixture::start(Setup {
        server,
        tail: format!("[mcp.dedicated]\nenabled = true\nport = {}\n", free_port()?),
        ..Setup::default()
    })
    .await?;
    let _subjects = store_mtls_ca(&fixture.state, client_ca()?.0.as_bytes())?;
    let mut change = McpOverrides::default();
    change.auth.dedicated.mtls = Some(MtlsMode::Required);
    change.auth.main.mtls = Some(MtlsMode::Optional);

    let restarted = fixture.supervisor.restart(fixture.plan(&change)?).await?;

    assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
    assert_eq!(fixture.revision()?, 1);
    let (main, dedicated) = (fixture.main()?, fixture.dedicated()?);
    for (address, mode) in [(dedicated, MtlsMode::Required), (main, MtlsMode::Optional)] {
        assert!(passes(address, &der, mode).await?, "{mode:?}");
        for other in [MtlsMode::Off, MtlsMode::Optional, MtlsMode::Required] {
            if other != mode {
                assert!(
                    !passes(address, &der, other).await?,
                    "{mode:?} as {other:?}"
                );
            }
        }
    }
    fixture.stop().await??;
    Ok(())
}

/// A TLS server on loopback answering `GET` with 200 under `mtls`'s client-certificate
/// rule; its address. The thread serves until the process ends.
fn serving(cert: &[u8], key: &[u8], mtls: MtlsMode) -> TestResult<SocketAddr> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(client_ca()?.1))?;
    let provider = Arc::new(default_provider());
    let versions = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let builder = match mtls {
        MtlsMode::Required => versions.with_client_cert_verifier(verifier.build()?),
        MtlsMode::Optional => {
            versions.with_client_cert_verifier(verifier.allow_unauthenticated().build()?)
        }
        MtlsMode::Off | _ => versions.with_no_client_auth(),
    };
    let config = Arc::new(builder.with_single_cert(
        vec![CertificateDer::from(cert.to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    )?);
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    drop(thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(connection) = ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = StreamOwned::new(connection, stream);
            let mut line = String::new();
            if BufReader::new(&mut tls).read_line(&mut line).is_ok() {
                drop(tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ));
                drop(tls.flush());
            }
        }
    }));
    Ok(address)
}

/// Todo 28: the probe passes only the expected client-certificate rule.
///
/// A listener must ask for a certificate and answer without one (`optional`), ask for one
/// and refuse without one (`required`), or never ask (`off`); every other listener fails
/// the health check, so a restart onto a listener that does not enforce `required` is
/// reverted. The listener's certificate stays pinned whatever the rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probe_passes_only_the_expected_client_certificate_rule() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (_lines, cert, key) = identity(files.path())?;
    let (_other_lines, other, _other_key) = identity(files.path())?;
    let modes = [MtlsMode::Off, MtlsMode::Optional, MtlsMode::Required];
    for served in modes {
        let address = serving(&cert, &key, served)?;
        for expected in modes {
            assert_eq!(
                passes(address, &cert, expected).await?,
                served == expected,
                "served {served:?}, expected {expected:?}"
            );
        }
        assert!(
            !passes(address, &other, served).await?,
            "{served:?} with another certificate than the pinned one"
        );
    }
    Ok(())
}

/// Todo 28: a client CA replacement restarts its listener or puts the CA back.
///
/// Replacing the client CA in use needs the password's confirmation and restarts the
/// listener using it; a failed restart puts the previous CA file back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_ca_replacement_restarts_its_listener_or_puts_the_ca_back() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (server, der, _key) = identity(files.path())?;
    let metrics = SocketAddr::from(([127, 0, 0, 1], free_port()?));
    let armed = Arc::new(AtomicBool::new(false));
    let held: Arc<Mutex<Vec<io::Result<TcpListener>>>> = Arc::default();
    let (arming, holding) = (Arc::clone(&armed), Arc::clone(&held));
    let fixture = Fixture::start(Setup {
        server,
        metrics: Some(metrics),
        windows: Some(SHORT),
        hook: hook(move |stage| {
            if stage == Stage::Stopped && arming.load(Ordering::SeqCst) {
                let taken = TcpListener::bind(metrics);
                if let Ok(mut slot) = holding.lock() {
                    slot.push(taken);
                }
            }
            async {}
        }),
        ..Setup::default()
    })
    .await?;
    let [first, second, third] = [client_ca()?.0, client_ca()?.0, client_ca()?.0];
    let _subjects = store_mtls_ca(&fixture.state, first.as_bytes())?;
    let mut optional = McpOverrides::default();
    optional.auth.main.mtls = Some(MtlsMode::Optional);
    let on = fixture.supervisor.restart(fixture.plan(&optional)?).await?;
    assert!(matches!(on, Restarted::Applied), "{on:?}");
    let stored = || fs::read_to_string(mtls_ca_path(&fixture.state));

    let unconfirmed = fixture
        .supervisor
        .replace_client_ca(second.clone().into_bytes(), false)
        .await;
    assert!(
        matches!(unconfirmed, Err(ListenerError::ConfirmationRequired)),
        "{unconfirmed:?}"
    );
    assert_eq!(stored()?, first, "unchanged");
    let before = fixture.supervisor.status().main.ok_or("main")?.generation;
    let replaced = fixture
        .supervisor
        .replace_client_ca(second.clone().into_bytes(), true)
        .await?;
    assert!(matches!(replaced, Restarted::Applied), "{replaced:?}");
    assert_eq!(stored()?, second);
    let after = fixture.supervisor.status().main.ok_or("main")?.generation;
    assert_eq!(after, before.saturating_add(1), "main restarted");
    assert!(passes(fixture.main()?, &der, MtlsMode::Optional).await?);

    armed.store(true, Ordering::SeqCst);
    let failed = fixture
        .supervisor
        .replace_client_ca(third.into_bytes(), true)
        .await?;

    assert!(
        matches!(
            failed,
            Restarted::Reverted(RevertReason::Health {
                listener: ListenerKind::Main,
                reason: _
            })
        ),
        "{failed:?}"
    );
    assert_eq!(stored()?, second, "the previous CA is back");
    assert!(passes(fixture.main()?, &der, MtlsMode::Optional).await?);
    assert!(
        held.lock()
            .map_err(|_poisoned| "poisoned")?
            .iter()
            .any(Result::is_ok),
        "the test held the metrics port"
    );
    fixture.stop().await??;
    Ok(())
}
