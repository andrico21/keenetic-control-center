//! Prometheus exporter against the 4.3 and 5.1 fake-router profiles.
//!
//! Every test runs on paused Tokio time: the cadence is the behavior under test, and the
//! fake router answers inside the same runtime, over a Unix socket on Unix and loopback TCP
//! elsewhere.
#![expect(
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions and fixtures define the contract"
)]

use core::{error::Error, time::Duration};
use std::{collections::BTreeSet, sync::Arc};

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
use tokio::{task, time::sleep};
use url::Url;

use crate::settle::settle;

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
    rig_with_routers(firmware, metrics_toml, &["fake"]).await
}

/// Like [`rig`], with every id of `ids` registered against the same fake router.
async fn rig_with_routers(
    firmware: Firmware,
    metrics_toml: &str,
    ids: &[&str],
) -> Result<Rig, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let router = FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?).build()?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let self_metrics = SelfMetrics::new("0.1.0-test")?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let profiles = RouterRegistry::new(state, &[], &outbound)?
        .with_rci_observers(self_metrics.rci_observers());
    // On Unix the clients reach the fake over its Unix socket: a paused clock can jump ahead
    // of a loopback TCP reply that is written but not yet readable.
    #[cfg(unix)]
    let (address, handle, registry) = {
        let (address, socket, handle) = router.serve_local()?;
        let registry = Arc::new(profiles.with_local_socket(address, socket));
        (address, handle, registry)
    };
    #[cfg(not(unix))]
    let ((address, handle), registry) = (
        router.serve(([127, 0, 0, 1], 0).into()).await?,
        Arc::new(profiles),
    );
    for id in ids {
        registry
            .create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                ManagedRouterProfile::new(
                    (*id).to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password.clone(),
                ),
            )
            .await?;
    }
    let config = Config::from_toml_str(&format!("[metrics]\nenabled = true\n{metrics_toml}"))?;
    config.validate()?;
    let poller = Poller::new(registry);
    let exporter = MetricsExporter::new(Arc::clone(&poller), &config.metrics, self_metrics)?;
    let prometheus = Registry::new();
    exporter.register(&prometheus)?;
    for id in ids {
        exporter.watch(id).await;
        settle("the first polling round", async || {
            Ok(poller.light_rounds(id).await >= 1)
        })
        .await?;
    }
    // The round's publish queued the exporter's follower, which runs before this task resumes.
    task::yield_now().await;
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

/// The `client` label values of the receive-byte series of `router`.
fn client_labels(text: &str, router: &str) -> BTreeSet<String> {
    samples(text, "keenetic_client_receive_bytes_total")
        .into_iter()
        .filter(|line| line.contains(&format!("router=\"{router}\"")))
        .filter_map(|line| line.split("client=\"").nth(1)?.split('"').next())
        .map(str::to_owned)
        .collect()
}

/// Whether `label` is `client-` and sixteen lowercase hex digits.
fn is_pseudonym(label: &str) -> bool {
    label.strip_prefix("client-").is_some_and(|hash| {
        hash.len() == 16
            && hash
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
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
        settle("the round at 120 s", async || {
            Ok(rig.poller.light_rounds("fake").await >= 5)
        })
        .await?;
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

/// `per_client = true, per_client_max = 3` exports 3 pseudonymous clients of 6, stable
/// across scrapes.
#[tokio::test(start_paused = true)]
async fn per_client_series_are_capped() -> TestResult {
    let rig = rig(Firmware::V5_1, "per_client = true\nper_client_max = 3\n").await?;
    let first = scrape(&rig.registry)?;
    let clients = client_labels(&first, "fake");
    assert_eq!(clients.len(), 3, "{clients:?}");
    assert!(
        clients.iter().all(|label| is_pseudonym(label)),
        "{clients:?}"
    );
    assert!(!first.contains("02:00:00:00:10:"), "pseudonyms, not MACs");
    let second = scrape(&rig.registry)?;
    assert_eq!(
        client_labels(&second, "fake"),
        clients,
        "stable across scrapes"
    );
    rig.handle.shutdown().await?;
    Ok(())
}

/// G-16: the dropped-series metric is a gauge of the series dropped at the latest scrape,
/// so scraping twice reports the same value and the old counter is gone.
#[tokio::test(start_paused = true)]
async fn dropped_series_gauge_does_not_grow_per_scrape() -> TestResult {
    let rig = rig(Firmware::V5_1, "per_client = true\nper_client_max = 3\n").await?;
    for scrape_number in 1_u8..=3_u8 {
        let text = scrape(&rig.registry)?;
        assert_eq!(
            samples(&text, "kcc_metrics_series_dropped"),
            ["kcc_metrics_series_dropped{router=\"fake\"} 3"],
            "scrape {scrape_number}"
        );
        assert!(
            samples(&text, "kcc_metrics_series_dropped_total").is_empty(),
            "the counter name is gone:\n{text}"
        );
    }
    rig.handle.shutdown().await?;
    Ok(())
}

/// G-18: the interface status series carries no free-text label; the description lives on
/// the info family.
#[tokio::test(start_paused = true)]
async fn interface_description_is_an_info_label_not_a_status_label() -> TestResult {
    let rig = rig(Firmware::V5_1, "").await?;
    let text = scrape(&rig.registry)?;
    let up = samples(&text, "keenetic_interface_up");
    assert!(!up.is_empty(), "{text}");
    let status_labels: BTreeSet<String> = ["router", "interface", "type"]
        .map(str::to_owned)
        .into_iter()
        .collect();
    for line in up {
        assert_eq!(label_names(line), status_labels, "{line}");
    }
    let info = samples(&text, "keenetic_interface_info");
    assert!(!info.is_empty(), "{text}");
    let info_labels: BTreeSet<String> = ["router", "interface", "description"]
        .map(str::to_owned)
        .into_iter()
        .collect();
    for line in info {
        assert_eq!(label_names(line), info_labels, "{line}");
        assert!(line.ends_with(" 1"), "{line}");
    }
    rig.handle.shutdown().await?;
    Ok(())
}

/// G-17: the same MAC on two routers yields different pseudonyms and the same one on every
/// scrape; the series per scrape are unchanged.
#[tokio::test(start_paused = true)]
async fn per_client_pseudonyms_are_scoped_to_the_router() -> TestResult {
    let rig = rig_with_routers(
        Firmware::V5_1,
        "per_client = true\nper_client_max = 3\n",
        &["fake", "fake-2"],
    )
    .await?;
    let first = scrape(&rig.registry)?;
    let one = client_labels(&first, "fake");
    let two = client_labels(&first, "fake-2");
    assert_eq!((one.len(), two.len()), (3, 3), "{first}");
    assert!(one.is_disjoint(&two), "{one:?} {two:?}");
    assert!(one.iter().chain(&two).all(|label| is_pseudonym(label)));
    let second = scrape(&rig.registry)?;
    assert_eq!(client_labels(&second, "fake"), one);
    assert_eq!(client_labels(&second, "fake-2"), two);
    rig.handle.shutdown().await?;
    Ok(())
}
