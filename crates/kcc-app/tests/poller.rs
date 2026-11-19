//! Poller integration tests.
#![expect(
    clippy::default_numeric_fallback,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration-test crate structure and bounded fixture loop"
)]

use core::{error::Error, time::Duration};
use std::sync::Arc;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    poller::{PollIntervals, Poller},
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn ten_subscribers_share_one_light_poll_round() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (registry, handle) =
        registry_for(&directory, FakeRouter::builder(Profile::default()).build()?).await?;
    let poller = Poller::with_intervals(
        registry,
        PollIntervals::new(
            Duration::from_secs(15),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(120),
        ),
    );
    let mut subscribers = Vec::new();
    for _index in 0..10 {
        subscribers.push(poller.subscribe("router").await);
    }
    for subscriber in &mut subscribers {
        timeout(Duration::from_secs(5), subscriber.changed()).await??;
        assert!(subscriber.borrow().as_ref().is_some_and(Result::is_ok));
    }
    assert_eq!(poller.light_rounds("router").await, 1);
    handle.shutdown().await?;
    Ok(())
}

/// Serves `router` and opens a registry holding it as router `router`.
///
/// On Unix the registry's clients reach the fake over its Unix socket: a paused clock can
/// jump ahead of a loopback TCP reply that is written but not yet readable.
///
/// # Errors
///
/// Bind, file, state-store, URL or registry failures.
// cancel-safe: dropping it drops the fake's handle and the half-built registry with it.
async fn registry_for(
    directory: &TempDir,
    router: FakeRouter,
) -> Result<(Arc<RouterRegistry>, Handle), Box<dyn Error>> {
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let profiles = RouterRegistry::new(state, &[], &outbound)?;
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
    registry
        .create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            ManagedRouterProfile::new(
                "router".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                "admin".to_owned(),
                password,
            ),
        )
        .await?;
    Ok((registry, handle))
}

/// Requests in `log` for `path`, optionally narrowed to one `name` query value.
fn count(log: &[kcc_testkit::RequestRecord], path: &str, name: Option<&str>) -> usize {
    log.iter()
        .filter(|record| record.path() == path)
        .filter(|record| {
            name.is_none_or(|wanted| {
                record
                    .query()
                    .iter()
                    .any(|(key, value)| key == "name" && value == wanted)
            })
        })
        .count()
}

/// A metrics-only subscription polls each resource once per its own interval.
///
/// Light resources once per `interval`, heavy ones once per `heavy_interval`, never NAT or
/// process tables; a later UI subscriber joins the same task.
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test(start_paused = true)]
async fn metrics_subscription_keeps_one_poller_at_its_own_cadence() -> Result<(), Box<dyn Error>> {
    use kcc_app::poller::MetricsCadence;
    use kcc_testkit::model::{Firmware, Model};
    use tokio::time::sleep;

    for firmware in [Firmware::V4_3, Firmware::V5_1] {
        let directory = TempDir::new()?;
        let router = FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?).build()?;
        let (registry, handle) = registry_for(&directory, router).await?;
        let poller = Poller::new(registry);
        poller.record_update_available("router", true).await;
        let mut metrics = poller
            .subscribe_metrics(
                "router",
                MetricsCadence::new(Duration::from_secs(30), Duration::from_secs(120)),
            )
            .await;
        timeout(Duration::from_secs(5), metrics.changed()).await??;
        // Rounds at 0, 30, 60, 90 and 120 s; heavy items at 0 and 120 s.
        sleep(Duration::from_secs(135)).await;
        // Each round publishes after it is counted; the round at 120 s may still be reading,
        // so wait for its publication. The first wait returns the earlier rounds' unseen one.
        for _publication in 0..2 {
            if poller.light_rounds("router").await >= 5 {
                break;
            }
            metrics.changed().await?;
        }
        let completed = poller.light_rounds("router").await;
        assert_eq!(completed, 5, "{firmware:?}: one light round per 30 s");
        let log = handle.request_log();
        let rounds = usize::try_from(completed)?;
        for path in [
            "/rci/show/system",
            "/rci/show/last-change",
            "/rci/show/internet/status",
        ] {
            assert_eq!(count(&log, path, None), rounds, "{firmware:?}: {path}");
        }
        assert_eq!(
            count(&log, "/rci/show/interface", None),
            rounds.saturating_add(2),
            "{firmware:?}: interface summary per light round plus identity detection per heavy round"
        );
        for interface in ["ISP", "Bridge0"] {
            assert_eq!(
                count(&log, "/rci/show/interface/stat", Some(interface)),
                rounds,
                "{firmware:?}: stat of up interface {interface}"
            );
        }
        for path in [
            "/rci/show/ip/hotspot",
            "/rci/show/media",
            "/rci/show/mws/member",
            "/rci/show/ip/dhcp/bindings",
        ] {
            assert_eq!(count(&log, path, None), 2, "{firmware:?}: heavy {path}");
        }
        assert!(
            log.iter().all(|record| !record.path().contains("/ip/nat")
                && !record.path().contains("/processes")),
            "{firmware:?}: NAT and process tables are never polled"
        );
        let latest = metrics.borrow_and_update().clone().ok_or("no snapshot")??;
        assert_eq!(latest.update_available, Some(true), "cached update flag");
        assert!(
            latest.interface_counters.get("Bridge0").is_some(),
            "counters of every up interface"
        );
        assert!(
            latest.interface_stats.get("Bridge0").is_none()
                && latest.interface_stats.get("ISP").is_some(),
            "the dashboard's WAN counters stay WAN-only"
        );
        assert!(
            latest.media.is_array() && latest.mesh_members.is_array(),
            "heavy metrics items"
        );
        assert_eq!(
            latest
                .internet_status
                .get("internet")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "internet status"
        );
        // A UI subscriber shares the task, which then follows the faster 15 s cadence.
        let _ui = poller.subscribe("router").await;
        sleep(Duration::from_secs(31)).await;
        let shared_rounds = poller.light_rounds("router").await;
        assert_eq!(
            count(&handle.request_log(), "/rci/show/system", None),
            usize::try_from(shared_rounds)?,
            "{firmware:?}: still one polling task"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
