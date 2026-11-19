//! The exporter while kcc runs: routers added and removed at runtime, the published
//! firmware-update flag, and the Web session gauge.
//!
//! Every test runs on paused Tokio time, as the other exporter tests do.
#![expect(
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions and fixtures define the contract"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::path::{Path, PathBuf};

#[path = "support/settle.rs"]
mod settle;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::{Config, OutboundConfig},
};
use kcc_telemetry::metrics::{
    instrumentation::SelfMetrics, registry_follow::follow_registry, service::MetricsExporter,
    web_sessions,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use prometheus::{Registry, TextEncoder};
use tempfile::TempDir;
use tokio::time::sleep;
use url::Url;

use crate::settle::settle;

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// An administrator for registry changes.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// A default fake router, served before the registry that reaches it is built, and the
/// password file of its profile.
struct Fake {
    /// The address of the profile URL.
    address: SocketAddr,
    /// The Unix socket the registry's clients dial for `address`.
    #[cfg(unix)]
    socket: PathBuf,
    /// Fake router control.
    handle: Handle,
    /// The profile's password file.
    password: PathBuf,
}

/// Serves a default fake router whose profile signs in with the password file `password`.
///
/// On Unix it answers on a Unix socket: a paused clock can jump ahead of a loopback TCP
/// reply that is written but not yet readable.
// cancel-safe: dropping it drops the fake's handle, which stops the fake.
#[cfg_attr(
    unix,
    expect(
        clippy::unused_async,
        reason = "only the loopback TCP fake of other platforms binds asynchronously"
    )
)]
async fn serve(password: &Path) -> Result<Fake, Box<dyn Error>> {
    let router = FakeRouter::builder(Profile::default()).build()?;
    #[cfg(unix)]
    let (address, socket, handle) = router.serve_local()?;
    #[cfg(not(unix))]
    let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
    Ok(Fake {
        address,
        #[cfg(unix)]
        socket,
        handle,
        password: password.to_owned(),
    })
}

/// Registers `fake` as router `id` and returns its handle.
// NOT cancel-safe: dropped after the registry wrote the profile, it loses the fake's handle
// and the fake stops under a registered router.
async fn add(registry: &RouterRegistry, id: &str, fake: Fake) -> Result<Handle, Box<dyn Error>> {
    registry
        .create(
            &admin(),
            ManagedRouterProfile::new(
                id.to_owned(),
                Url::parse(&format!("http://{}", fake.address))?,
                "admin".to_owned(),
                fake.password,
            ),
        )
        .await?;
    Ok(fake.handle)
}

/// The scrape text of `registry`.
fn scrape(registry: &Registry) -> Result<String, Box<dyn Error>> {
    Ok(TextEncoder::new().encode_to_string(&registry.gather())?)
}

/// Whether `text` has a series of `router`.
fn exports(text: &str, router: &str) -> bool {
    let label = format!("router=\"{router}\"");
    text.lines()
        .any(|line| line.starts_with("keenetic_") && line.contains(&label))
}

/// A registry with router `a`, the shared poller and an exporter following the registry.
struct Rig {
    /// Password file and state.
    _directory: TempDir,
    /// Router profiles.
    registry: Arc<RouterRegistry>,
    /// Shared poller.
    poller: Arc<Poller>,
    /// The exporter.
    exporter: Arc<MetricsExporter>,
    /// The scrape registry.
    prometheus: Registry,
    /// Router `a`.
    handle: Handle,
    /// A second fake router, not registered yet: the registry can reach it once a test
    /// adds it.
    spare: Fake,
}

/// Builds the rig and lets the first round complete.
async fn rig() -> Result<Rig, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let state = StateStore::open(&directory.path().join("state"))?;
    let first = serve(&password).await?;
    let spare = serve(&password).await?;
    #[cfg(unix)]
    let registry = Arc::new(
        RouterRegistry::new(state, &[], &outbound)?
            .with_local_socket(first.address, first.socket.clone())
            .with_local_socket(spare.address, spare.socket.clone()),
    );
    #[cfg(not(unix))]
    let registry = Arc::new(RouterRegistry::new(state, &[], &outbound)?);
    let handle = add(&registry, "a", first).await?;
    let config = Config::from_toml_str("[metrics]\nenabled = true\n")?;
    let poller = Poller::new(Arc::clone(&registry));
    let exporter = Arc::new(MetricsExporter::new(
        Arc::clone(&poller),
        &config.metrics,
        SelfMetrics::new("0.1.0-test")?,
    )?);
    let prometheus = Registry::new();
    exporter.register(&prometheus)?;
    drop(follow_registry(
        Arc::clone(&exporter),
        Arc::clone(&registry),
    ));
    settle("router a polled", async || {
        Ok(scrape(&prometheus)?.contains("keenetic_up{router=\"a\"} 1"))
    })
    .await?;
    Ok(Rig {
        _directory: directory,
        registry,
        poller,
        exporter,
        prometheus,
        handle,
        spare,
    })
}

#[tokio::test(start_paused = true)]
async fn routers_added_and_removed_at_runtime_follow_the_registry() -> TestResult {
    let rig = rig().await?;
    assert!(
        exports(&scrape(&rig.prometheus)?, "a"),
        "the startup router"
    );
    let added = add(&rig.registry, "b", rig.spare).await?;
    settle("router b polled", async || {
        Ok(scrape(&rig.prometheus)?.contains("keenetic_up{router=\"b\"} 1"))
    })
    .await?;
    let text = scrape(&rig.prometheus)?;
    assert!(
        text.contains("keenetic_up{router=\"b\"} 1"),
        "the added router is scraped:\n{text}"
    );
    assert_eq!(rig.exporter.watched(), ["a", "b"], "watched");

    rig.registry.delete(&admin(), "b").await?;
    settle("router b unwatched", async || {
        Ok(rig.exporter.watched() == ["a"])
    })
    .await?;
    let after = scrape(&rig.prometheus)?;
    assert!(
        !exports(&after, "b"),
        "the removed router is gone:\n{after}"
    );
    assert!(exports(&after, "a"), "the other router stays");
    assert_eq!(rig.exporter.watched(), ["a"], "unwatched");
    added.shutdown().await?;
    rig.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_recorded_update_flag_reaches_the_scrape() -> TestResult {
    let rig = rig().await?;
    let family = "keenetic_firmware_update_available{router=\"a\"}";
    assert!(
        !scrape(&rig.prometheus)?.contains(family),
        "not checked yet"
    );
    rig.poller.record_update_available("a", true).await;
    let flagged = format!("{family} 1");
    // The paused clock stands still while this waits: no further polling round runs.
    settle("published without waiting for the next round", async || {
        Ok(scrape(&rig.prometheus)?.contains(&flagged))
    })
    .await?;
    rig.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_session_gauge_follows_the_count_every_interval() -> TestResult {
    let metrics = SelfMetrics::new("0.1.0-test")?;
    let prometheus = Registry::new();
    metrics.register(&prometheus)?;
    let count = Arc::new(AtomicUsize::new(2));
    let source = Arc::clone(&count);
    let tracker = web_sessions::track(metrics, move || {
        let sessions = source.load(Ordering::SeqCst);
        async move { sessions }
    });
    settle("the count at once", async || {
        Ok(scrape(&prometheus)?.contains("kcc_web_sessions 2"))
    })
    .await?;
    count.store(5, Ordering::SeqCst);
    sleep(web_sessions::WEB_SESSIONS_INTERVAL).await;
    settle("the count after one interval", async || {
        Ok(scrape(&prometheus)?.contains("kcc_web_sessions 5"))
    })
    .await?;
    tracker.abort();
    Ok(())
}
