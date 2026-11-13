//! Explicit persistence, rollback, and timer-loss recovery.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::permissions::Permission;
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    configuration::{
        SafetyNet,
        bracket::ArmedFate,
        close::{Close, Closed, close},
    },
};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use tokio::time::timeout;

use super::{Applier, ApplyError};
use crate::source::SourceConfig;

/// Commits only a successfully verified, unfinished apply.
///
/// # Errors
/// Returns invalid lifecycle, conflict, or save failures.
// NOT cancel-safe: commit can persist before the caller receives its result.
pub(super) async fn commit(applier: &mut Applier) -> Result<(), ApplyError> {
    if !applier.report.verified || applier.report.finished {
        return Err(ApplyError::Verification);
    }
    applier
        .changes
        .ensure_unchanged()
        .await
        .map_err(|_error| ApplyError::Drift)?;
    let ctx = context(applier)
        .await
        .map_err(|_error| ApplyError::FinishFailed)?;
    let save = (Close::Save, Permission::Migrate);
    let _: Closed = close(&mut applier.changes, &ctx, applier.mode, save)
        .await
        .map_err(|error| match (error.fate(), error.applied()) {
            (Some(ArmedFate::Saved), _) => ApplyError::SavedDisarmFailed,
            (None, true) => ApplyError::CommittedSaveFailed,
            (Some(_) | None, _) => ApplyError::FinishFailed,
        })?;
    applier.report.finished = true;
    Ok(())
}

/// Disarms recovery for a verified, unfinished apply and persists nothing.
///
/// # Errors
/// Returns invalid lifecycle, conflict, or disarm failures.
// NOT cancel-safe: the disarm can reach the router before the caller receives its result.
pub(super) async fn keep_unsaved(applier: &mut Applier) -> Result<(), ApplyError> {
    if !applier.report.verified || applier.report.finished {
        return Err(ApplyError::Verification);
    }
    applier
        .changes
        .ensure_unchanged()
        .await
        .map_err(|_error| ApplyError::Drift)?;
    let ctx = context(applier).await?;
    let keep = (Close::KeepUnsaved, Permission::Migrate);
    let _: Closed = close(&mut applier.changes, &ctx, applier.mode, keep)
        .await
        .map_err(|_error| ApplyError::DisarmFailed)?;
    applier.report.finished = true;
    Ok(())
}

/// Requests explicit router rollback, then checks original startup identity.
///
/// Rolling back a verified run is the user's choice and needs
/// [`SafetyNet::CONTROL_PERMISSION`]; rolling back a failed run is the run's own recovery
/// and is sent under its `Migrate`.
///
/// # Errors
/// Returns workflow, reconnect, or identity mismatch errors.
// NOT cancel-safe: rollback may reboot before its response is received.
pub(super) async fn rollback(applier: &mut Applier) -> Result<(), ApplyError> {
    if applier.report.finished {
        return Err(ApplyError::Validation);
    }
    let permission = if applier.report.failure.is_some() {
        Permission::Migrate
    } else {
        SafetyNet::CONTROL_PERMISSION
    };
    let ctx = context(applier).await?;
    let closed = close(
        &mut applier.changes,
        &ctx,
        applier.mode,
        (Close::Rollback, permission),
    )
    .await
    .map_err(|_error| ApplyError::FinishFailed)?;
    if wait_restored(applier).await.is_err() {
        return Err(if closed.restarting {
            ApplyError::RollbackRestarting
        } else {
            ApplyError::FinishFailed
        });
    }
    applier.report.finished = true;
    Ok(())
}

/// The router context of the applier's current connection.
///
/// # Errors
/// Returns unreachability or an unsupported firmware catalog.
// cancel-safe: a single detection read.
async fn context(applier: &Applier) -> Result<RouterCtx, ApplyError> {
    let client = applier.changes.client();
    let catalog = Catalog::for_router(
        &client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?,
    )
    .map_err(|_error| ApplyError::Validation)?;
    Ok(RouterCtx::new(Arc::clone(&client), catalog))
}

/// Waits out the armed timer and proves the original configuration returned.
///
/// # Errors
/// Returns the typed router rollback outcome or an unproven recovery failure.
// cancel-safe: waiting and recovery probes do not mutate the router.
pub(super) async fn recover(applier: &mut Applier) -> Result<(), ApplyError> {
    let elapsed = applier.options.clock.now().saturating_sub(applier.armed_at);
    let remaining = Duration::from_secs(applier.options.safety_seconds.saturating_add(1))
        .saturating_sub(elapsed);
    applier.options.clock.wait(remaining).await;
    wait_restored(applier).await?;
    applier.report.finished = true;
    Err(ApplyError::RolledBackByRouter)
}

/// Waits for original credentials and startup state after an explicit or timed rollback.
///
/// # Errors
/// Returns unreachability after the bounded recovery window.
// NOT cancel-safe: the local credential is restored after a successful router probe.
async fn wait_restored(applier: &mut Applier) -> Result<(), ApplyError> {
    timeout(Duration::from_secs(120), async {
        for _attempt in 0..120_u16 {
            if applier
                .changes
                .restore_connection(Arc::clone(&applier.original))
                .await
                .is_ok()
                && original_restored(applier).await.is_ok()
            {
                return Ok(());
            }
            applier.options.clock.wait(Duration::from_secs(1)).await;
        }
        Err(ApplyError::Unreachable)
    })
    .await
    .map_err(|_elapsed| ApplyError::Unreachable)?
}

/// Verifies both running and startup match the saved pre-change startup body.
///
/// # Errors
/// Returns unreachability or mismatched rollback identity.
// cancel-safe: only downloads configuration.
async fn original_restored(applier: &Applier) -> Result<(), ApplyError> {
    let before = SourceConfig::from_bytes(applier.backup.expose_secret())
        .map_err(|_error| ApplyError::Verification)?;
    for kind in [ConfigKind::Startup, ConfigKind::Running] {
        let bytes = applier
            .changes
            .client()
            .download_config(kind)
            .await
            .map_err(|_error| ApplyError::Unreachable)?;
        let after = SourceConfig::from_bytes(bytes.expose_secret())
            .map_err(|_error| ApplyError::Verification)?;
        if before.header.md5 != after.header.md5 {
            return Err(ApplyError::Verification);
        }
    }
    Ok(())
}
