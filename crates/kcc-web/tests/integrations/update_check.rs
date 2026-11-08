//! The firmware-update check behind the dashboard badge.
//!
//! A first dashboard load starts the check in the background and shows "Not checked";
//! the next load shows the result, published to the poller for the metrics. Within the
//! six-hour TTL no load asks the router again; after it the next one does. A router no
//! poll follows is never asked.

extern crate alloc;

use alloc::sync::Arc;

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::firmware_update::FirmwareUpdate;
use kcc_web::{
    fleet::{UPDATE_CHECK_TTL, UpdateCheck as _, UpdateStatus},
    fleet_updates::ComponentsUpdateCheck,
};

use crate::{
    support::{Fixture, ROUTER, TestResult},
    wiring::{HandClock, Options, text},
};

/// The dashboard of the fake router.
const DASHBOARD: &str = "/ui/r/home";

/// The router command the check sends.
const CHECK: &str = "components check-update";

/// The update flag the poller publishes for the metrics.
async fn published(fixture: &Fixture) -> TestResult<Option<bool>> {
    match fixture.poller().latest(ROUTER).await {
        Some(Ok(snapshot)) => Ok(snapshot.update_available),
        Some(Err(error)) => Err(error.into()),
        None => Err("the router is not polled".into()),
    }
}

/// "Update available: 5.1.4" in English.
fn available() -> String {
    let mut args = FluentArgs::new();
    args.set("version", "5.1.4");
    tr(Locale::En, keys::WEB_UPDATE_AVAILABLE, Some(&args))
}

#[tokio::test]
async fn an_available_update_is_checked_once_per_ttl_and_published() -> TestResult {
    let mut fixture = Fixture::new(Options::update(FirmwareUpdate::Available(
        "5.1.4".to_owned(),
    )))
    .await?;
    let viewer = fixture.login().await?;
    let first = text(fixture.get(DASHBOARD, &viewer).await?).await?;
    assert!(
        first.contains(&tr(Locale::En, keys::WEB_UPDATE_UNKNOWN, None)),
        "the first load does not wait for the check"
    );
    assert_eq!(
        fixture.finished().await?,
        UpdateStatus::Available {
            version: "5.1.4".to_owned()
        }
    );
    for load in 0_u8..2 {
        let page = text(fixture.get(DASHBOARD, &viewer).await?).await?;
        assert!(page.contains(&available()), "load {load}: the badge");
    }
    assert_eq!(fixture.commands(CHECK), 1, "one check within the TTL");
    assert!(!fixture.another_check(), "no second check started");
    assert_eq!(published(&fixture).await?, Some(true), "the metric flag");

    fixture.clock().advance(UPDATE_CHECK_TTL);
    drop(fixture.get(DASHBOARD, &viewer).await?);
    drop(fixture.finished().await?);
    assert_eq!(fixture.commands(CHECK), 2, "checked again after the TTL");
    Ok(())
}

#[tokio::test]
async fn a_current_router_shows_up_to_date() -> TestResult {
    let mut fixture = Fixture::new(Options::update(FirmwareUpdate::Current)).await?;
    let viewer = fixture.login().await?;
    drop(fixture.get(DASHBOARD, &viewer).await?);
    assert_eq!(fixture.finished().await?, UpdateStatus::Current);
    let page = text(fixture.get(DASHBOARD, &viewer).await?).await?;
    assert!(
        page.contains(&tr(Locale::En, keys::WEB_UPDATE_CURRENT, None)),
        "up to date"
    );
    assert_eq!(published(&fixture).await?, Some(false), "the metric flag");
    Ok(())
}

#[tokio::test]
async fn a_router_no_poll_follows_is_not_asked() -> TestResult {
    let fixture = Fixture::new(Options::update(FirmwareUpdate::Available(
        "5.1.4".to_owned(),
    )))
    .await?;
    let check = ComponentsUpdateCheck::new(
        Arc::clone(fixture.registry()),
        Arc::clone(fixture.poller()),
        Arc::<HandClock>::clone(fixture.clock()),
    );
    let before = fixture.handle().request_count();
    assert_eq!(check.check(ROUTER).await, UpdateStatus::Unknown);
    check.refresh().await;
    assert_eq!(fixture.handle().request_count(), before, "no request");
    Ok(())
}
