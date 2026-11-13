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
    time::Duration,
};
use std::path::Path;

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

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// An administrator for registry changes.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// Serves a default fake router and registers it as `id`.
async fn add(
    registry: &RouterRegistry,
    id: &str,
    password: &Path,
) -> Result<Handle, Box<dyn Error>> {
    let router = FakeRouter::builder(Profile::default()).build()?;
    let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    registry
        .create(
            &admin(),
            ManagedRouterProfile::new(
                id.to_owned(),
                Url::parse(&format!("http://{address}"))?,
                "admin".to_owned(),
                password.to_owned(),
            ),
        )
        .await?;
    Ok(handle)
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
    directory: TempDir,
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
}

/// Builds the rig and lets the first round complete.
async fn rig() -> Result<Rig, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = Arc::new(RouterRegistry::new(state, &[], &outbound)?);
    let handle = add(&registry, "a", &password).await?;
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
    sleep(Duration::from_secs(1)).await;
    Ok(Rig {
        directory,
        registry,
        poller,
        exporter,
        prometheus,
        handle,
    })
}

#[tokio::test(start_paused = true)]
async fn routers_added_and_removed_at_runtime_follow_the_registry() -> TestResult {
    let rig = rig().await?;
    assert!(
        exports(&scrape(&rig.prometheus)?, "a"),
        "the startup router"
    );
    let password = rig.directory.path().join("password");
    let added = add(&rig.registry, "b", &password).await?;
    sleep(Duration::from_secs(1)).await;
    let text = scrape(&rig.prometheus)?;
    assert!(
        text.contains("keenetic_up{router=\"b\"} 1"),
        "the added router is scraped:\n{text}"
    );
    assert_eq!(rig.exporter.watched(), ["a", "b"], "watched");

    rig.registry.delete(&admin(), "b").await?;
    sleep(Duration::from_secs(1)).await;
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
    sleep(Duration::from_secs(1)).await;
    assert!(
        scrape(&rig.prometheus)?.contains(&format!("{family} 1")),
        "published without waiting for the next round"
    );
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
    sleep(Duration::from_millis(1)).await;
    assert!(
        scrape(&prometheus)?.contains("kcc_web_sessions 2"),
        "at once"
    );
    count.store(5, Ordering::SeqCst);
    sleep(web_sessions::WEB_SESSIONS_INTERVAL).await;
    assert!(
        scrape(&prometheus)?.contains("kcc_web_sessions 5"),
        "after one interval"
    );
    tracker.abort();
    Ok(())
}
