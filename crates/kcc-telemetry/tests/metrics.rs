//! Prometheus exporter against the 4.3 and 5.1 fake-router profiles.
//!
//! Every test runs on paused Tokio time: the cadence is the behavior under test, and the
//! fake router answers over loopback inside the same runtime.
#![expect(
    clippy::absolute_paths,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions and fixtures define the contract"
)]

use core::{error::Error, net::SocketAddr, time::Duration};
use std::{collections::BTreeSet, sync::Arc};

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::{Config, OutboundConfig},
};
use kcc_telemetry::metrics::{
    catalogue::{FAMILIES, Presence},
    instrumentation::SelfMetrics,
    service::MetricsExporter,
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, RequestRecord,
    model::{Firmware, Model, Profile},
};
use prometheus::{Registry, TextEncoder};
use tempfile::TempDir;
use tokio::time::sleep;
use url::Url;

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// One fake router, the shared poller and a registered exporter.
struct Rig {
    /// Holds the password file and state directory.
    _directory: TempDir,
    /// Fake router control.
    handle: Handle,
    /// Shared poller.
    poller: Arc<Poller>,
    /// Exporter under test (kept alive for its watchers).
    _exporter: MetricsExporter,
    /// Registry the exporter is registered on.
    registry: Registry,
}

/// Starts a KN-1811 fake router on `firmware`, a registry with RCI observers, the shared
/// poller and an exporter for `metrics_toml`, and waits for the first polling round.
async fn rig(firmware: Firmware, metrics_toml: &str) -> Result<Rig, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let router = FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?).build()?;
    let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let password = directory.path().join("password");
    std::fs::write(&password, DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let self_metrics = SelfMetrics::new("0.1.0-test")?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = Arc::new(
        RouterRegistry::new(state, &[], &outbound)?
            .with_rci_observers(self_metrics.rci_observers()),
    );
    registry
        .create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            ManagedRouterProfile::new(
                "fake".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                "admin".to_owned(),
                password,
            ),
        )
        .await?;
    let config = Config::from_toml_str(&format!("[metrics]\nenabled = true\n{metrics_toml}"))?;
    config.validate()?;
    let poller = Poller::new(registry);
    let exporter = MetricsExporter::new(Arc::clone(&poller), &config.metrics, self_metrics)?;
    let prometheus = Registry::new();
    exporter.register(&prometheus)?;
    exporter.watch("fake").await;
    // The first round completes before virtual time can reach 1 s.
    sleep(Duration::from_secs(1)).await;
    Ok(Rig {
        _directory: directory,
        handle,
        poller,
        _exporter: exporter,
        registry: prometheus,
    })
}

/// Renders the registry in the text exposition format.
fn scrape(registry: &Registry) -> Result<String, Box<dyn Error>> {
    Ok(TextEncoder::new().encode_to_string(&registry.gather())?)
}

/// Sample lines of `name` (exact family name, suffixes excluded).
fn samples<'text>(text: &'text str, name: &str) -> Vec<&'text str> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter(|line| {
            line.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .collect()
}

/// Label names of one sample line.
fn label_names(line: &str) -> BTreeSet<String> {
    let Some((_, rest)) = line.split_once('{') else {
        return BTreeSet::new();
    };
    let mut names = BTreeSet::new();
    let mut remaining = rest;
    while let Some((name, value)) = remaining.split_once("=\"") {
        let _inserted: bool = names.insert(name.trim_start_matches(',').to_owned());
        let mut escaped = false;
        let end = value.char_indices().find(|&(_, character)| {
            let closes = character == '"' && !escaped;
            escaped = character == '\\' && !escaped;
            closes
        });
        remaining = end.map_or("", |(index, _)| {
            value.get(index.saturating_add(1)..).unwrap_or("")
        });
    }
    names
}

/// Requests in `log` for exactly `path`.
fn count(log: &[RequestRecord], path: &str) -> usize {
    log.iter().filter(|record| record.path() == path).count()
}

/// Every always-present family appears with exactly its catalogue labels, per-client
/// series stay off by default, and the self-metrics count the poller's requests.
#[tokio::test(start_paused = true)]
async fn scrape_has_every_family_with_its_labels() -> TestResult {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let rig = rig(firmware, "").await?;
        let text = scrape(&rig.registry)?;
        for family in FAMILIES
            .iter()
            .filter(|family| family.presence == Presence::Always)
        {
            let lines = samples(&text, family.name);
            assert!(!lines.is_empty(), "{firmware:?}: {} missing", family.name);
            let expected: BTreeSet<String> = family
                .labels
                .iter()
                .map(|label| (*label).to_owned())
                .collect();
            for line in lines {
                assert_eq!(label_names(line), expected, "{firmware:?}: {line}");
                assert!(line.contains("router=\"fake\""), "{firmware:?}: {line}");
            }
        }
        assert!(
            FAMILIES
                .iter()
                .filter(|family| family.presence == Presence::PerClient)
                .all(|family| samples(&text, family.name).is_empty()),
            "{firmware:?}: no per-client series by default"
        );
        assert!(
            !text.contains("02:00:00:00:10:"),
            "{firmware:?}: no client MACs"
        );
        assert_eq!(
            samples(&text, "keenetic_up"),
            ["keenetic_up{router=\"fake\"} 1"],
            "{firmware:?}"
        );
        for name in [
            "kcc_build_info",
            "kcc_router_requests_total",
            "kcc_router_request_duration_seconds_count",
            "kcc_router_auth_total",
        ] {
            assert!(!samples(&text, name).is_empty(), "{firmware:?}: {name}");
        }
        assert!(
            text.contains("kcc_router_requests_total{outcome=\"ok\",router=\"fake\"}"),
            "{firmware:?}: RCI observer"
        );
        rig.handle.shutdown().await?;
    }
    Ok(())
}

/// Scrapes render the cache only; the shared poller keeps the metrics cadence.
///
/// With no UI subscriber each light resource is read once per `interval`, heavy ones once
/// per `heavy_interval`, and the NAT and process tables never.
#[tokio::test(start_paused = true)]
async fn scrapes_never_reach_the_router_and_polling_keeps_its_cadence() -> TestResult {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let rig = rig(firmware, "").await?;
        let before = rig.handle.request_count();
        for _scrape in 0_u8..20 {
            drop(scrape(&rig.registry)?);
        }
        assert_eq!(rig.handle.request_count(), before, "{firmware:?}: scrapes");
        // Rounds at 0, 30, 60, 90 and 120 s; heavy items at 0 and 120 s.
        sleep(Duration::from_secs(134)).await;
        let rounds = usize::try_from(rig.poller.light_rounds("fake").await)?;
        assert_eq!(rounds, 5, "{firmware:?}: one light round per interval");
        let log = rig.handle.request_log();
        for path in [
            "/rci/show/system",
            "/rci/show/internet/status",
            "/rci/show/last-change",
        ] {
            assert_eq!(count(&log, path), rounds, "{firmware:?}: {path}");
        }
        for path in [
            "/rci/show/ip/hotspot",
            "/rci/show/media",
            "/rci/show/mws/member",
        ] {
            assert_eq!(count(&log, path), 2, "{firmware:?}: heavy {path}");
        }
        assert!(
            log.iter().all(|record| !record.path().contains("/ip/nat")
                && !record.path().contains("/processes")),
            "{firmware:?}: NAT and process tables are never polled"
        );
        rig.handle.shutdown().await?;
    }
    Ok(())
}

/// After the router stops, data older than 3 intervals is dropped and `keenetic_up` is 0.
#[tokio::test(start_paused = true)]
async fn stale_cache_drops_series_and_reports_down() -> TestResult {
    let rig = rig(Firmware::V5_1, "").await?;
    rig.handle.shutdown().await?;
    sleep(Duration::from_secs(60)).await;
    let fresh = scrape(&rig.registry)?;
    assert_eq!(
        samples(&fresh, "keenetic_up"),
        ["keenetic_up{router=\"fake\"} 1"]
    );
    assert_eq!(
        samples(&fresh, "kcc_poller_errors_total"),
        ["kcc_poller_errors_total{router=\"fake\"} 1"],
        "the failed round at 30 s"
    );
    sleep(Duration::from_secs(31)).await;
    let stale = scrape(&rig.registry)?;
    assert_eq!(
        samples(&stale, "keenetic_up"),
        ["keenetic_up{router=\"fake\"} 0"]
    );
    assert!(
        !stale
            .lines()
            .any(|line| line.starts_with("keenetic_") && !line.starts_with("keenetic_up")),
        "no stale router series:\n{stale}"
    );
    Ok(())
}

/// `per_client = true, per_client_max = 3` exports 3 pseudonymous clients of 6 and counts
/// the 3 dropped series on every scrape.
#[tokio::test(start_paused = true)]
async fn per_client_series_are_capped_and_counted() -> TestResult {
    let rig = rig(Firmware::V5_1, "per_client = true\nper_client_max = 3\n").await?;
    let first = scrape(&rig.registry)?;
    let clients: BTreeSet<&str> = samples(&first, "keenetic_client_receive_bytes_total")
        .into_iter()
        .filter_map(|line| line.split("client=\"").nth(1)?.split('"').next())
        .collect();
    assert_eq!(
        clients,
        BTreeSet::from(["client-1", "client-2", "client-3"])
    );
    assert!(!first.contains("02:00:00:00:10:"), "pseudonyms, not MACs");
    assert_eq!(
        samples(&first, "kcc_metrics_series_dropped_total"),
        ["kcc_metrics_series_dropped_total{router=\"fake\"} 3"]
    );
    let second = scrape(&rig.registry)?;
    assert_eq!(
        samples(&second, "kcc_metrics_series_dropped_total"),
        ["kcc_metrics_series_dropped_total{router=\"fake\"} 6"]
    );
    rig.handle.shutdown().await?;
    Ok(())
}
