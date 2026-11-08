//! The firmware-update check behind the dashboard badge and the
//! `keenetic_firmware_update_available` metric.
//!
//! [`ComponentsUpdateCheck`] sends the catalog-validated `components check-update`
//! action, which changes no configuration, outside the change workflow. It keeps one
//! result per router for [`UPDATE_CHECK_TTL`] and starts at most one check per router in
//! that time, whether a page load or [`ComponentsUpdateCheck::refresh`] asks. It sends
//! nothing for a router whose latest polling round failed or that no poll follows (its
//! catalog comes from that round), and publishes every result through
//! [`Poller::record_update_available`].

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, pin::Pin};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_app::{accounts::Clock, poller::Poller, registry::RouterRegistry};
use kcc_catalog::Catalog;
use kcc_domain::{RouterCtx, components};
use kcc_rci::RciBody;
use serde_json::Value;

use crate::fleet::{UPDATE_CHECK_TTL, UpdateCheck, UpdateStatus};

/// [`UpdateCheck`] over the components domain's check, cached per router.
#[non_exhaustive]
pub struct ComponentsUpdateCheck {
    /// Router profiles and clients.
    registry: Arc<RouterRegistry>,
    /// The shared poller: the online test, the catalog source and the publisher.
    poller: Arc<Poller>,
    /// Decides when a result expires.
    clock: Arc<dyn Clock>,
    /// The latest result and check start of every router.
    results: Mutex<BTreeMap<String, Checked>>,
}

impl fmt::Debug for ComponentsUpdateCheck {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComponentsUpdateCheck")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

/// One router's latest known result.
#[derive(Debug, Clone)]
struct Checked {
    /// The latest result a check produced.
    status: UpdateStatus,
    /// Unix time the running or latest completed check started; `None` lets the next
    /// request check again (the previous check could not reach the router).
    started: Option<u64>,
}

impl ComponentsUpdateCheck {
    /// A check over `registry`, publishing to `poller` and timed by `clock`.
    #[inline]
    #[must_use]
    pub fn new(registry: Arc<RouterRegistry>, poller: Arc<Poller>, clock: Arc<dyn Clock>) -> Self {
        Self {
            registry,
            poller,
            clock,
            results: Mutex::new(BTreeMap::new()),
        }
    }

    /// Checks every registered router whose result is due; routers that are offline or
    /// not polled cost no request.
    // cancel-safe: a cancelled check leaves its router due again only after the TTL; no
    // configuration is changed.
    #[inline]
    pub async fn refresh(&self) {
        let routers = match self.registry.list() {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%error, "firmware update refresh could not list routers");
                return;
            }
        };
        for entry in routers {
            drop(self.status(&entry.profile.id).await);
        }
    }

    /// The cached status of `router`, checking it first when due.
    async fn status(&self, router: &str) -> UpdateStatus {
        let (due, previous) = self.claim(router);
        if !due {
            return previous;
        }
        let checked = self.run(router).await;
        self.settle(router, &checked);
        if checked == UpdateStatus::Unknown {
            previous
        } else {
            checked
        }
    }

    /// Whether a check of `router` is due, marking it started when it is, and the cached
    /// status. A check is due when none started in the last [`UPDATE_CHECK_TTL`].
    fn claim(&self, router: &str) -> (bool, UpdateStatus) {
        let now = self.clock.unix_seconds();
        let mut results = lock(&self.results);
        let entry = results.entry(router.to_owned()).or_insert(Checked {
            status: UpdateStatus::Unknown,
            started: None,
        });
        let fresh = entry
            .started
            .is_some_and(|started| now.saturating_sub(started) < UPDATE_CHECK_TTL.as_secs());
        if !fresh {
            entry.started = Some(now);
        }
        let cached = entry.status.clone();
        drop(results);
        (!fresh, cached)
    }

    /// Stores a completed check: a known result replaces the cached one, an unknown one
    /// makes the router due again and keeps the last known status.
    fn settle(&self, router: &str, checked: &UpdateStatus) {
        if let Some(entry) = lock(&self.results).get_mut(router) {
            if *checked == UpdateStatus::Unknown {
                entry.started = None;
            } else {
                entry.status = checked.clone();
            }
        }
    }

    /// Asks `router` once and publishes a known result.
    async fn run(&self, router: &str) -> UpdateStatus {
        let status = self.ask(router).await;
        let available = match &status {
            UpdateStatus::Available { version: _ } => true,
            UpdateStatus::Current => false,
            UpdateStatus::Unknown => return status,
        };
        self.poller.record_update_available(router, available).await;
        tracing::info!(router, available, "firmware update check completed");
        status
    }

    /// The router's answer; [`UpdateStatus::Unknown`] without a request when the router
    /// is offline, not polled, or its catalog lacks the command.
    async fn ask(&self, router: &str) -> UpdateStatus {
        let Some(Ok(snapshot)) = self.poller.latest(router).await else {
            return UpdateStatus::Unknown;
        };
        let Ok(catalog) = Catalog::for_router(&snapshot.info) else {
            return UpdateStatus::Unknown;
        };
        let client = match self.registry.client(router).await {
            Ok(client) => client,
            Err(error) => {
                tracing::debug!(%error, router, "firmware update check has no client");
                return UpdateStatus::Unknown;
            }
        };
        let context = RouterCtx::new(client, catalog);
        let Some(line) = components::plan_check_update(&context)
            .ok()
            .and_then(|operation| {
                operation
                    .requests
                    .first()
                    .map(|request| request.path.clone())
            })
        else {
            return UpdateStatus::Unknown;
        };
        match context.client.parse(&line).await {
            Ok(RciBody::Json(answer)) => interpret(&answer.value),
            Ok(_) => UpdateStatus::Unknown,
            Err(error) => {
                tracing::debug!(%error, router, "firmware update check failed");
                UpdateStatus::Unknown
            }
        }
    }
}

impl UpdateCheck for ComponentsUpdateCheck {
    #[inline]
    fn check<'call>(
        &'call self,
        router: &'call str,
    ) -> Pin<Box<dyn Future<Output = UpdateStatus> + Send + 'call>> {
        Box::pin(self.status(router))
    }
}

/// The router's answer to `components check-update`: `available` and, when newer
/// firmware exists, its `version` (shape UNVERIFIED on real firmware).
fn interpret(answer: &Value) -> UpdateStatus {
    match answer.get("available").and_then(Value::as_bool) {
        Some(true) => answer
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .map_or(UpdateStatus::Unknown, |version| UpdateStatus::Available {
                version: version.to_owned(),
            }),
        Some(false) => UpdateStatus::Current,
        None => UpdateStatus::Unknown,
    }
}

/// The result map; a panic while holding it cannot leave an entry half-written, so a
/// poisoned lock is used as is.
fn lock(results: &Mutex<BTreeMap<String, Checked>>) -> MutexGuard<'_, BTreeMap<String, Checked>> {
    results.lock().unwrap_or_else(PoisonError::into_inner)
}
