//! Explicit persistence, rollback, and timer-loss recovery.
//!
//! A verified, unfinished apply runs under its armed recovery timer. Every failure of a
//! finish before its closing step is sent (a change made after verification, a lost
//! router detection) leaves that timer armed, so it is [`ApplyError::FinishFailed`],
//! which every surface reports as still armed.

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
/// Returns invalid lifecycle failures, [`ApplyError::SavedDisarmFailed`] when the
/// configuration was saved but the timer could not be disarmed, and
/// [`ApplyError::FinishFailed`] (still armed) for every other failure.
// NOT cancel-safe: commit can persist before the caller receives its result.
pub(super) async fn commit(applier: &mut Applier) -> Result<(), ApplyError> {
    if !applier.report.verified || applier.report.finished {
        return Err(ApplyError::Verification);
    }
    let ctx = armed_context(applier).await?;
    let save = (Close::Save, Permission::Migrate);
    let _: Closed = close(&mut applier.changes, &ctx, applier.mode, save)
        .await
        .map_err(|error| match error.fate() {
            Some(ArmedFate::Saved) => ApplyError::SavedDisarmFailed,
            Some(_) | None => ApplyError::FinishFailed,
        })?;
    applier.report.finished = true;
    Ok(())
}

/// Disarms recovery for a verified, unfinished apply and persists nothing.
///
/// # Errors
/// Returns invalid lifecycle failures, [`ApplyError::FinishFailed`] (still armed) when it
/// fails before the disarm is sent, or [`ApplyError::DisarmFailed`].
// NOT cancel-safe: the disarm can reach the router before the caller receives its result.
pub(super) async fn keep_unsaved(applier: &mut Applier) -> Result<(), ApplyError> {
    if !applier.report.verified || applier.report.finished {
        return Err(ApplyError::Verification);
    }
    let ctx = armed_context(applier).await?;
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
/// A failed run that already ended (the router or kcc restored the saved configuration
/// and kcc proved it) has nothing left to roll back: it succeeds and sends nothing.
///
/// # Errors
/// Returns [`ApplyError::Validation`] for a finished successful run,
/// [`ApplyError::FinishFailed`] (still armed) when the rollback could not be sent or
/// confirmed, or reconnect and identity mismatch errors after it.
// NOT cancel-safe: rollback may reboot before its response is received.
pub(super) async fn rollback(applier: &mut Applier) -> Result<(), ApplyError> {
    if applier.report.finished {
        return match applier.report.failure {
            Some(_) => Ok(()),
            None => Err(ApplyError::Validation),
        };
    }
    let permission = if applier.report.failure.is_some() {
        Permission::Migrate
    } else {
        SafetyNet::CONTROL_PERMISSION
    };
    let ctx = context(applier)
        .await
        .map_err(|_error| ApplyError::FinishFailed)?;
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

/// Proves that nothing changed the router since verification and returns the context of
/// the applier's current connection.
///
/// # Errors
/// [`ApplyError::FinishFailed`]: a change since verification or a lost detection leaves
/// the recovery timer armed.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, two reads.
async fn armed_context(applier: &Applier) -> Result<RouterCtx, ApplyError> {
    applier
        .changes
        .ensure_unchanged()
        .await
        .map_err(|_error| ApplyError::FinishFailed)?;
    context(applier)
        .await
        .map_err(|_error| ApplyError::FinishFailed)
}

/// The router context of the applier's current connection.
///
/// # Errors
/// Returns unreachability or an unsupported firmware catalog.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single detection read.
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
// NOT cancel-safe: it awaits `wait_restored`, which may already have switched the change set
// back to the original connection when dropped, and dropped before the end it leaves
// `report.finished` unset although the router may have rolled back.
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, only downloads configuration.
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
