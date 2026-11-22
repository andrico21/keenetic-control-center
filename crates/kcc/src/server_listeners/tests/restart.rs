//! Main listener restarts.
//!
//! The Web session, health and metrics survive; invalid settings, a held metrics port, a
//! pinned CA-signed certificate, keys revoked or unreadable while the new generation
//! registers.

extern crate alloc;

mod tls;

use alloc::sync::Arc;
use core::net::{IpAddr, SocketAddr};
use std::{fs, net::TcpListener, sync::Mutex};

use kcc_app::{
    api_keys::ApiKeysDocument, mcp_settings::ListenerKind, settings::mcp_schema::Endpoint,
};
use kcc_testkit::toml_text::path;
use kcc_web::admin::AuthReload as _;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use reqwest::StatusCode;
use url::Url;

use super::{
    SHORT, TestResult, bounded,
    client::{account, http, initialize_status, sign_in, status, text},
    endpoint,
    fixture::{Fixture, Setup, free_port},
    holding, hook,
};
use crate::server_listeners::{
    ListenerError, Restarted, RevertReason, build::BuildError, supervisor::Stage,
};

/// The main listener's generation number.
fn generation(fixture: &Fixture) -> TestResult<u64> {
    Ok(fixture
        .supervisor
        .status()
        .main
        .ok_or("no main listener")?
        .generation)
}

/// Todo 26: a main restart keeps a signed-in Web session valid and `/healthz` answering.
///
/// After two restarts `/metrics` serves the `kcc_` and `rmcp_server_kit_` series; the
/// state watcher got the first generation's address once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_main_restart_keeps_the_web_session_health_and_metrics() -> TestResult {
    let mut fixture = Fixture::start(Setup::default()).await?;
    let client = http()?;
    let first = fixture.main()?;
    let session = sign_in(&client, first).await?;

    for value in [Endpoint::Both, Endpoint::Main] {
        let restarted = fixture
            .supervisor
            .restart(fixture.plan(&endpoint(value))?)
            .await?;
        assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
        assert_eq!(
            status(&client, fixture.main()?, "/healthz").await?,
            StatusCode::OK
        );
        assert_eq!(
            account(&client, fixture.main()?, &session).await?,
            StatusCode::OK
        );
    }

    assert_eq!(generation(&fixture)?, 3);
    let scraped = text(&client, fixture.metrics, "/metrics").await?;
    assert!(scraped.contains("\nkcc_"), "{scraped}");
    assert!(
        scraped.contains("\nrmcp_server_kit_http_requests_total"),
        "{scraped}"
    );
    assert_eq!((&mut fixture.first).await?, first);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: settings the new generation cannot be built from are refused before anything
/// stops: the old main generation keeps serving and nothing is saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_settings_keep_the_old_generation() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let mut change = endpoint(Endpoint::Both);
    change.dedicated.enabled = Some(true);
    change.dedicated.bind = Some(IpAddr::from([192, 0, 2, 1]));
    change.dedicated.public_url = Some(Url::parse("https://mcp.example.test/")?);

    let refused = fixture.supervisor.restart(fixture.plan(&change)?).await;

    assert!(
        matches!(
            refused,
            Err(ListenerError::Build {
                source: BuildError::PlaintextBeyondLoopback,
                listener: _,
            })
        ),
        "{refused:?}"
    );
    assert_eq!(generation(&fixture)?, 1);
    assert_eq!(
        status(&http()?, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    assert_eq!(fixture.revision()?, 0);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a metrics port taken while the main listener restarts fails the new
/// generation's health check: the restart reverts and the main listener serves again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_metrics_port_reverts_the_restart() -> TestResult {
    let metrics = SocketAddr::from(([127, 0, 0, 1], free_port()?));
    let held = Arc::new(Mutex::new(None));
    let taken = Arc::clone(&held);
    let fixture = Fixture::start(Setup {
        metrics: Some(metrics),
        windows: Some(SHORT),
        hook: hook(move |stage| {
            if stage == Stage::Stopped {
                let listener = TcpListener::bind(metrics);
                if let Ok(mut slot) = taken.lock() {
                    *slot = Some(listener);
                }
            }
            async {}
        }),
        ..Setup::default()
    })
    .await?;
    let previous = fixture.main()?;

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
    assert_eq!(fixture.main()?, previous);
    assert_eq!(generation(&fixture)?, 3, "a third generation serves again");
    assert!(
        held.lock()
            .map_err(|_poisoned| "poisoned")?
            .as_ref()
            .is_some_and(Result::is_ok),
        "the test held the metrics port"
    );
    assert_eq!(
        status(&http()?, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    assert_eq!(fixture.revision()?, 0);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: the health check pins the configured certificate, so one signed by a CA the
/// probe does not know passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ca_signed_certificate_passes_the_pinned_health_check() -> TestResult {
    let files = tempfile::TempDir::new()?;
    let mut authority = CertificateParams::new(Vec::<String>::new())?;
    authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = CertifiedIssuer::self_signed(authority, KeyPair::generate()?)?;
    let key = KeyPair::generate()?;
    let leaf =
        CertificateParams::new(vec!["kcc.example.test".to_owned()])?.signed_by(&key, &issuer)?;
    let cert = files.path().join("cert.pem");
    fs::write(&cert, format!("{}{}", leaf.pem(), issuer.pem()))?;
    let key_file = kcc_testkit::write_secret_file(files.path(), "key.pem", &key.serialize_pem())?;
    let fixture = Fixture::start(Setup {
        server: format!(
            "tls_cert_path = {}\ntls_key_path = {}",
            path(&cert),
            path(&key_file)
        ),
        ..Setup::default()
    })
    .await?;

    let restarted = fixture
        .supervisor
        .restart(fixture.plan(&endpoint(Endpoint::Both))?)
        .await?;

    assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
    assert_eq!(generation(&fixture)?, 2);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a key revoked through the reload fan-out after the new generation was built
/// but before it registered is refused by it: registering installs the current keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_revoked_before_registration_is_refused() -> TestResult {
    let (hook, mut holds) = holding(&[Stage::Serving]);
    let fixture = Fixture::start(Setup {
        hook,
        ..Setup::default()
    })
    .await?;
    let client = http()?;
    assert_eq!(
        initialize_status(&client, fixture.main()?, &fixture.key).await?,
        StatusCode::OK
    );
    let restart = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&endpoint(Endpoint::Both))?),
    );

    drop(holds.until(Stage::Serving).await?);
    fixture.state.write(&ApiKeysDocument::default())?;
    fixture.reload.reload_keys()?;
    holds.release_all()?;

    let restarted = bounded(restart).await???;
    assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
    assert_eq!(
        initialize_status(&client, fixture.main()?, &fixture.key).await?,
        StatusCode::UNAUTHORIZED
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: keys that cannot be read when the new generation registers fail the restart,
/// which reverts; the previous generation serves again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_keys_at_registration_revert_the_restart() -> TestResult {
    let (hook, mut holds) = holding(&[Stage::Serving]);
    let fixture = Fixture::start(Setup {
        hook,
        ..Setup::default()
    })
    .await?;
    let restart = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&endpoint(Endpoint::Both))?),
    );

    drop(holds.until(Stage::Serving).await?);
    fs::write(fixture.state.dir().join("api_keys.json"), "{")?;
    holds.release_all()?;

    let restarted = bounded(restart).await???;
    assert!(
        matches!(
            restarted,
            Restarted::Reverted(RevertReason::Register {
                listener: ListenerKind::Main,
                reason: _,
            })
        ),
        "{restarted:?}"
    );
    assert_eq!(
        status(&http()?, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    assert_eq!(fixture.revision()?, 0);
    fixture.stop().await??;
    Ok(())
}
