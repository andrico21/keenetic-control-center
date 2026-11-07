//! Explicit persistence, rollback, and timer-loss recovery.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    permissions::Permission,
    workflow::{CliCommand as ValidatedCli, TerminalCliChangeRequest},
};
use kcc_catalog::{Catalog, HttpMethod};
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use serde_json::json;
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
    match applier.mode {
        SafetyMode::Router => {
            applier
                .changes
                .commit()
                .await
                .map_err(|_error| ApplyError::Workflow)?;
            applier
                .changes
                .save()
                .await
                .map_err(|_error| ApplyError::Workflow)?;
        }
        SafetyMode::ScheduledReboot => {
            applier
                .changes
                .save()
                .await
                .map_err(|_error| ApplyError::Workflow)?;
            let client = applier.changes.client();
            let catalog = Catalog::for_router(
                &client
                    .detect()
                    .await
                    .map_err(|_error| ApplyError::Unreachable)?,
            )
            .map_err(|_error| ApplyError::Validation)?;
            let ctx = RouterCtx::new(Arc::clone(&client), catalog);
            drop(
                SafetyNet::disarm(&mut applier.changes, &ctx, applier.mode)
                    .await
                    .map_err(|_error| ApplyError::Workflow)?,
            );
        }
        _ => return Err(ApplyError::Validation),
    }
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
    let client = applier.changes.client();
    let catalog = Catalog::for_router(
        &client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?,
    )
    .map_err(|_error| ApplyError::Validation)?;
    let ctx = RouterCtx::new(Arc::clone(&client), catalog);
    drop(
        SafetyNet::disarm(&mut applier.changes, &ctx, applier.mode)
            .await
            .map_err(|_error| ApplyError::Workflow)?,
    );
    applier.report.finished = true;
    Ok(())
}

/// Requests explicit router rollback, then checks original startup identity.
///
/// # Errors
/// Returns workflow, reconnect, or identity mismatch errors.
// NOT cancel-safe: rollback may reboot before its response is received.
pub(super) async fn rollback(applier: &mut Applier) -> Result<(), ApplyError> {
    if applier.report.finished {
        return Err(ApplyError::Validation);
    }
    let client = applier.changes.client();
    let catalog = Catalog::for_router(
        &client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?,
    )
    .map_err(|_error| ApplyError::Validation)?;
    let path = match applier.mode {
        SafetyMode::Router => "system configuration fail-safe rollback",
        SafetyMode::ScheduledReboot => "system reboot",
        _ => return Err(ApplyError::Validation),
    };
    let validated = catalog
        .validate(path, HttpMethod::Post, &json!({}))
        .map_err(|_issues| ApplyError::Validation)?;
    let request = TerminalCliChangeRequest::new(
        vec![ValidatedCli::new(path.to_owned(), validated)],
        Permission::Destructive,
        json!({}),
    );
    drop(
        applier
            .changes
            .apply_cli_terminal(request)
            .await
            .map_err(|_error| ApplyError::Workflow)?,
    );
    wait_restored(applier).await?;
    applier.report.finished = true;
    Ok(())
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
