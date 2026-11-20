//! The backup: the router's startup configuration into the encrypted backup store, as
//! `scheduled-<id>`. A read job; nothing on the router changes.

extern crate alloc;

use alloc::sync::Arc;
use core::str;

use kcc_app::{backups::BackupStore, jobs::JobTarget, registry::RouterRegistry};
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};
use tokio::task::spawn_blocking;

use super::{ActionDeps, ActionResult, Call, failed};
use crate::server_schedules::TARGET;

/// Backs up `call`'s router.
// NOT cancel-safe: see `ActionDeps::in_job`.
pub(super) async fn store(deps: &ActionDeps, call: &Call<'_>) -> ActionResult {
    let registry = Arc::clone(&deps.registry);
    let backups = Arc::clone(&deps.backups);
    let router = call.schedule.router.clone();
    let reason = format!("scheduled-{}", call.schedule.id);
    let target = JobTarget::Read(Some(router.clone()));
    deps.in_job("backup", target, move || {
        run(registry, backups, (router, reason))
    })
    .await
}

/// The job's work.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session; dropped while the backup is written, the write completes unreported.
async fn run(
    registry: Arc<RouterRegistry>,
    backups: Arc<BackupStore>,
    (router, reason): (String, String),
) -> ActionResult {
    let Ok(client) = registry.client(&router).await else {
        return failed("router");
    };
    let Ok(bytes) = client.download_config(ConfigKind::Startup).await else {
        return failed("router");
    };
    let Ok(plain) = str::from_utf8(bytes.expose_secret()) else {
        return failed("not_utf8");
    };
    let text = SecretString::from(plain.to_owned());
    match spawn_blocking(move || backups.create(&router, &reason, &text)).await {
        Ok(Ok(_info)) => ActionResult::Done {
            unsaved: false,
            checksum: None,
            job: None,
        },
        Ok(Err(error)) => {
            tracing::warn!(target: TARGET, %error, "a scheduled backup was not stored");
            failed("backup")
        }
        Err(_joined) => failed("backup"),
    }
}
