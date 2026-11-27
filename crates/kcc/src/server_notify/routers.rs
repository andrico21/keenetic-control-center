//! One follower task per registered router while a router event is selected.
//!
//! Each holds a poll subscription (so the router is polled at the Web UI's cadence while
//! kcc runs) and turns the results into offline, online, refused-login, firmware and
//! new-device messages. Routers added or removed later start or lose their follower at once; a
//! removed router's task ends, which drops its subscription and forgets its state.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use std::sync::PoisonError;

use kcc_app::{
    notify_store::NotifyEvent,
    poller::{PollError, PollResult, Snapshot},
    pseudonym,
};
use kcc_domain::clients::Client;
use kcc_i18n::locale::Locale;
use kcc_web::fleet::UpdateStatus;
use serde::Deserialize as _;
use serde_json::Value;
use tokio::task::{JoinHandle, spawn_blocking};

use super::{
    Shared,
    arrivals::{Arrivals, Device},
    health::{Poll, RouterTracker, Transition},
    memory, render,
};

/// A router's follower task, aborted when dropped.
#[derive(Debug)]
struct Follow(JoinHandle<()>);

impl Drop for Follow {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps one follower per registered router while router events are wanted.
// cancel-safe: dropping it drops, and so aborts, every follower.
pub(super) async fn supervise(shared: Arc<Shared>) {
    let mut profiles = shared.deps.registry.subscribe_changes();
    let mut watching = shared.watching.subscribe();
    let mut followers: BTreeMap<String, Follow> = BTreeMap::new();
    loop {
        let wanted = if *watching.borrow_and_update() {
            match shared.deps.registry.list() {
                Ok(entries) => Some(entries.into_iter().map(|entry| entry.profile.id).collect()),
                Err(error) => {
                    tracing::warn!(%error, "notifier cannot list the routers");
                    None
                }
            }
        } else {
            Some(BTreeSet::new())
        };
        if let Some(routers) = wanted {
            reconcile(&shared, &mut followers, &routers);
        }
        tokio::select! {
            edited = profiles.changed() => if edited.is_err() { return; },
            toggled = watching.changed() => if toggled.is_err() { return; },
        }
    }
}

/// Starts followers for `routers` and drops the others.
fn reconcile(
    shared: &Arc<Shared>,
    followers: &mut BTreeMap<String, Follow>,
    routers: &BTreeSet<String>,
) {
    followers.retain(|router, _follow| routers.contains(router));
    for router in routers {
        if !followers.contains_key(router) {
            let task = tokio::spawn(follow(Arc::clone(shared), router.clone()));
            drop(followers.insert(router.clone(), Follow(task)));
        }
    }
}

/// The state one router's follower keeps, in memory only.
#[derive(Debug, Default)]
struct Watch {
    /// Reachability.
    tracker: RouterTracker,
    /// New devices.
    arrivals: Arrivals,
}

/// Follows `router`'s poll results until aborted.
// cancel-safe: each result is handled whole or not at all; aborting drops the
// subscription and the router's in-memory state.
async fn follow(shared: Arc<Shared>, router: String) {
    let mut results = shared.deps.poller.subscribe(&router).await;
    let mut watch = Watch::default();
    loop {
        let latest = results.borrow_and_update().clone();
        if let Some(result) = latest {
            observe(&shared, &router, &mut watch, &result).await;
        }
        if results.changed().await.is_err() {
            return;
        }
    }
}

/// Handles one poll result.
// cancel-safe: the only await records a firmware version, whose message follows it.
async fn observe(shared: &Shared, router: &str, watch: &mut Watch, result: &PollResult) {
    let now = shared.deps.clock.unix_seconds();
    let poll = match result {
        Ok(_) => Poll::Answered,
        Err(PollError::Auth) => Poll::LoginRefused,
        Err(_) => Poll::Failed,
    };
    let called = shared.router_name(router);
    match watch.tracker.observe(poll, now, shared.muted(router, now)) {
        None => {}
        Some(Transition::Down { since }) => {
            let shown = shared.local_time(since);
            shared.emit(NotifyEvent::RouterDownUp, |locale| {
                render::router_down(locale, &called, &shown)
            });
        }
        Some(Transition::Up { outage }) => shared.emit(NotifyEvent::RouterDownUp, |locale| {
            render::router_up(locale, &called, outage)
        }),
        Some(Transition::LoginRefused) => shared.emit(NotifyEvent::RouterLogin, |locale| {
            render::router_login(locale, &called)
        }),
    }
    if let Ok(snapshot) = result {
        if snapshot.update_available == Some(true) && shared.wants(NotifyEvent::FirmwareUpdate) {
            firmware(shared, router).await;
        }
        if shared.wants(NotifyEvent::NewDevice) {
            if let Some(clients) = hotspot(snapshot) {
                watch.arrivals.observe(&clients);
            }
        } else {
            watch.arrivals = Arrivals::default();
        }
    }
    if let Some(devices) = watch.arrivals.due(now) {
        let naming = if shared.client_details() {
            Naming::Details
        } else {
            Naming::Pseudonym(router)
        };
        shared.emit(NotifyEvent::NewDevice, |locale| {
            let named: Vec<String> = devices
                .iter()
                .map(|device| name(locale, device, naming))
                .collect();
            render::new_devices(locale, &called, &named)
        });
    }
}

/// Announces the firmware the update check found for `router`, once per version.
// cancel-safe: the version is remembered before the write, so a dropped write only loses
// the record across a restart.
async fn firmware(shared: &Shared, router: &str) {
    let (status, _due) = shared.deps.updates.cached(router);
    let UpdateStatus::Available { version } = status else {
        return;
    };
    let fresh = shared
        .firmware
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .offer(router, &version);
    if !fresh {
        return;
    }
    let state = shared.deps.state.clone();
    let (owned_router, owned_version) = (router.to_owned(), version.clone());
    match spawn_blocking(move || memory::record(&state, owned_router, owned_version)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "the announced firmware cannot be recorded"),
        Err(error) => tracing::warn!(%error, "recording the announced firmware did not finish"),
    }
    shared.emit(NotifyEvent::FirmwareUpdate, |locale| {
        render::firmware(locale, &shared.router_name(router), &version)
    });
}

/// The hotspot rows of `snapshot`, as a list or wrapped in `host`; `None` before the
/// list was read.
fn hotspot(snapshot: &Snapshot) -> Option<Vec<Client>> {
    let rows = snapshot
        .hotspot
        .as_array()
        .or_else(|| snapshot.hotspot.get("host").and_then(Value::as_array))?;
    Some(
        rows.iter()
            .filter_map(|row| Client::deserialize(row).ok())
            .collect(),
    )
}

/// How messages name clients.
#[derive(Clone, Copy, Debug)]
enum Naming<'router> {
    /// By their pseudonym on this router.
    Pseudonym(&'router str),
    /// By name and MAC (client details on).
    Details,
}

/// How a message names `device`; never by its address.
fn name(locale: Locale, device: &Device, naming: Naming<'_>) -> String {
    match naming {
        Naming::Pseudonym(router) => pseudonym::client(router, device.mac()),
        Naming::Details => device.name().map_or_else(
            || device.mac().to_owned(),
            |known| render::client_details(locale, known, device.mac()),
        ),
    }
}
