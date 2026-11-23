//! A failed client CA replacement leaves the previous CA in force: on disk and in the
//! listener that serves again.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    fs, io,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Mutex,
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
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use reqwest::Client;
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use super::{
    SHORT, TestResult,
    fixture::{Fixture, Setup, free_port},
    hook,
};
use crate::server_listeners::{ListenerError, Restarted, RevertReason, supervisor::Stage};

/// A client CA: its PEM and its signer.
struct Ca {
    /// The CA certificate as PEM.
    pem: String,
    /// Signs client certificates.
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    /// A self-signed CA named `name`.
    fn new(name: &str) -> TestResult<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate()?;
        let pem = params.self_signed(&key)?.pem();
        Ok(Self {
            pem,
            issuer: Issuer::new(params, key),
        })
    }

    /// An HTTPS client trusting `server` and presenting a certificate this CA signed.
    fn client(&self, server: &CertificateDer<'static>) -> TestResult<Client> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, "client");
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        let mut roots = RootCertStore::empty();
        roots.add(server.clone())?;
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )?;
        Ok(Client::builder()
            .use_preconfigured_tls(config)
            .timeout(Duration::from_secs(10))
            .build()?)
    }
}

/// A self-signed `localhost`/127.0.0.1 certificate and its key in `directory`: the
/// `[server]` lines serving TLS with them, the key file and the certificate's DER.
fn identity(directory: &Path) -> TestResult<(String, PathBuf, CertificateDer<'static>)> {
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?
        .self_signed(&key)?;
    let cert_file = directory.join("server-cert.pem");
    fs::write(&cert_file, cert.pem())?;
    let key_file =
        kcc_testkit::write_secret_file(directory, "server-key.pem", &key.serialize_pem())?;
    let lines = format!(
        "tls_cert_path = {}\ntls_key_path = {}",
        path(&cert_file),
        path(&key_file)
    );
    Ok((lines, key_file, cert.der().clone()))
}

/// Whether `client` gets an HTTP answer from `address` (its certificate was admitted).
async fn admitted(client: &Client, address: SocketAddr) -> bool {
    client
        .get(format!("https://{address}/healthz"))
        .send()
        .await
        .is_ok()
}

/// Main with `mtls = "optional"` and `second`'s CA stored.
async fn optional_main(setup: Setup, second: &Ca) -> TestResult<Fixture> {
    let fixture = Fixture::start(setup).await?;
    let _subjects = store_mtls_ca(&fixture.state, second.pem.as_bytes())?;
    let mut optional = McpOverrides::default();
    optional.auth.main.mtls = Some(MtlsMode::Optional);
    let on = fixture.supervisor.restart(fixture.plan(&optional)?).await?;
    if !matches!(on, Restarted::Applied) {
        return Err(format!("{on:?}").into());
    }
    Ok(fixture)
}

/// Todo 28: after a failed client CA replacement the listener trusts the previous CA.
///
/// The restart onto the new CA fails its health check; the CA file is put back before
/// the previous listener serves again, so a client certificate from the rejected CA is
/// refused and one from the previous CA is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_replacement_serves_with_the_previous_ca() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (server, _key_file, der) = identity(files.path())?;
    let metrics = SocketAddr::from(([127, 0, 0, 1], free_port()?));
    let armed = Arc::new(AtomicBool::new(false));
    let held: Arc<Mutex<Vec<io::Result<TcpListener>>>> = Arc::default();
    let (arming, holding) = (Arc::clone(&armed), Arc::clone(&held));
    let (second, third) = (Ca::new("Previous CA")?, Ca::new("Rejected CA")?);
    let setup = Setup {
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
    };
    let fixture = optional_main(setup, &second).await?;
    let (previous, rejected) = (second.client(&der)?, third.client(&der)?);
    assert!(admitted(&previous, fixture.main()?).await, "before");
    assert!(!admitted(&rejected, fixture.main()?).await, "before");

    armed.store(true, Ordering::SeqCst);
    let failed = fixture
        .supervisor
        .replace_client_ca(third.pem.clone().into_bytes(), true)
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
    assert!(
        held.lock()
            .map_err(|_poisoned| "poisoned")?
            .iter()
            .any(Result::is_ok),
        "the test held the metrics port"
    );
    assert_eq!(
        fs::read_to_string(mtls_ca_path(&fixture.state))?,
        second.pem
    );
    assert!(admitted(&previous, fixture.main()?).await, "previous CA");
    assert!(!admitted(&rejected, fixture.main()?).await, "rejected CA");
    fixture.stop().await??;
    Ok(())
}

/// Todo 28: a replacement whose new listener cannot be built puts the previous CA back.
///
/// The main TLS key is gone when the CA is replaced, so the build fails after the store:
/// the replacement reports the build error, the previous CA file is back byte for byte and
/// the running listener keeps trusting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_that_cannot_build_puts_the_ca_back() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let (server, key_file, der) = identity(files.path())?;
    let (second, third) = (Ca::new("Previous CA")?, Ca::new("Rejected CA")?);
    let fixture = optional_main(
        Setup {
            server,
            ..Setup::default()
        },
        &second,
    )
    .await?;
    let before = fs::read(mtls_ca_path(&fixture.state))?;
    fs::remove_file(&key_file)?;

    let failed = fixture
        .supervisor
        .replace_client_ca(third.pem.clone().into_bytes(), true)
        .await;

    assert!(
        matches!(
            failed,
            Err(ListenerError::Build {
                listener: "main",
                source: _
            })
        ),
        "{failed:?}"
    );
    assert_eq!(fs::read(mtls_ca_path(&fixture.state))?, before);
    assert!(admitted(&second.client(&der)?, fixture.main()?).await);
    fixture.stop().await??;
    Ok(())
}
