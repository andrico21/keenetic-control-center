//! The reboot: the router restarts, and the run succeeds only when it answers again.
//!
//! The router's offline and online messages are muted first, for 15 minutes. After the
//! restart was sent (inside a job, under a bracket guard), the router is asked for
//! `show system` every 15 s, outside any bracket, for up to 15 minutes: it is back when
//! its uptime is shorter than the time since the restart was sent plus 60 s.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::sync::OnceLock;

use kcc_app::{
    audit::Actor, jobs::JobTarget, permissions::Role, registry::RouterRegistry,
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{RouterCtx, system};
use tokio::time::{Instant, sleep, timeout};

use super::{ActionDeps, ActionResult, Call, failed, failure};
use crate::server_schedules::Timings;

/// Margin between the uptime of a router that came back and the time since its restart.
const UPTIME_MARGIN: Duration = Duration::from_secs(60);

/// What the job needs, owned.
struct Restart {
    /// Router profiles.
    registry: Arc<RouterRegistry>,
    /// The change workflow.
    workflow: Arc<ChangeWorkflow>,
    /// The router.
    router: String,
    /// `system:schedule:<id>`.
    actor: Actor,
    /// The owner's role.
    role: Role,
    /// When the restart was sent.
    sent: Arc<OnceLock<Instant>>,
}

/// Restarts `call`'s router and waits until it answers again.
// NOT cancel-safe: see `ActionDeps::in_job`; dropped while waiting, the outcome is lost.
pub(super) async fn restart(deps: &ActionDeps, call: &Call<'_>) -> ActionResult {
    let router = call.schedule.router.clone();
    if let Some(notify) = &deps.notify {
        let mute = i64::try_from(deps.timings.reboot_mute.as_secs()).unwrap_or(i64::MAX);
        let until = u64::try_from(call.now.saturating_add(mute)).unwrap_or(0);
        notify.mute_router(&router, until);
    }
    let sent = Arc::new(OnceLock::new());
    let restart = Restart {
        registry: Arc::clone(&deps.registry),
        workflow: Arc::clone(&deps.workflow),
        router: router.clone(),
        actor: call.actor.clone(),
        role: call.role.clone(),
        sent: Arc::clone(&sent),
    };
    let result = deps
        .in_job("reboot", JobTarget::Write(router.clone()), move || {
            send(restart)
        })
        .await;
    let (
        ActionResult::Done {
            unsaved: _,
            checksum: _,
            job: done_in,
        },
        Some(&at),
    ) = (&result, sent.get())
    else {
        return result;
    };
    let job = done_in.clone();
    if came_back(&deps.registry, &router, at, deps.timings).await {
        ActionResult::Done {
            unsaved: false,
            checksum: None,
            job,
        }
    } else {
        ActionResult::Failed {
            code: "did_not_come_back",
            job,
        }
    }
}

/// The job's work: the restart through the change workflow, under a bracket guard.
// NOT cancel-safe: dropped after the request is sent, the router may restart unaudited.
async fn send(restart: Restart) -> ActionResult {
    let _bracket = restart.workflow.brackets().enter();
    let mut changes = match restart
        .workflow
        .begin(&restart.router, restart.actor.clone(), &restart.role, false)
        .await
    {
        Ok(changes) => changes,
        Err(error) => return failure(&error),
    };
    let Ok(info) = restart.registry.poll_info(&restart.router).await else {
        return failed("router");
    };
    let Ok(catalog) = Catalog::for_router(&info) else {
        return failed("router");
    };
    let router = RouterCtx::new(changes.client(), catalog);
    let _first: Result<(), Instant> = restart.sent.set(Instant::now());
    match system::reboot(&mut changes, &router).await {
        Ok(_answer) => ActionResult::Done {
            unsaved: false,
            checksum: None,
            job: None,
        },
        Err(error) => failure(&error),
    }
}

/// Whether `router` answers within the wait with an uptime that started after `sent`.
// NOT cancel-safe: each probe may sign in first, and a sign-in dropped mid-way can leave an
// orphaned router session. Apart from that, reads.
async fn came_back(
    registry: &RouterRegistry,
    router: &str,
    sent: Instant,
    timings: Timings,
) -> bool {
    let deadline = sent.checked_add(timings.reboot_wait).unwrap_or(sent);
    loop {
        sleep(timings.reboot_probe).await;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        if let Ok(Some(uptime)) = timeout(left, uptime(registry, router)).await {
            let since = sent.elapsed().saturating_add(UPTIME_MARGIN);
            if Duration::from_secs(uptime) < since {
                return true;
            }
        }
    }
}

/// The router's uptime in seconds, when it answers.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
async fn uptime(registry: &RouterRegistry, router: &str) -> Option<u64> {
    let info = registry.poll_info(router).await.ok()?;
    let catalog = Catalog::for_router(&info).ok()?;
    let client = registry.client(router).await.ok()?;
    let state = system::read_system(&RouterCtx::new(client, catalog))
        .await
        .ok()?;
    state.uptime?.parse().ok()
}
