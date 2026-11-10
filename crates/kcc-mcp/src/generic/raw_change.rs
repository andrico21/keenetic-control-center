//! Permission, confirmation and recovery for raw mutations.

use kcc_app::{permissions::Permission, workflow::ChangeSet};
use kcc_catalog::Risk;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use kcc_rci::{RciError, capabilities::SystemMode};

use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers, support::errors::map_workflow,
};

/// Checks risk before router discovery, including the permission needed for recovery.
pub(super) fn authorize(
    server: &KccMcp,
    target: (&McpIdentity, &RouterId),
    confirmation: (Risk, bool),
) -> Result<(), McpFailure> {
    let (risk, confirm) = confirmation;
    server.require_destructive(
        if risk >= Risk::Management {
            Risk::Destructive
        } else {
            risk
        },
        confirm,
    )?;
    if risk >= Risk::Management {
        authorize_routers(
            target.0,
            Permission::Destructive,
            core::slice::from_ref(target.1),
        )?;
        if !confirm {
            return Err(McpFailure::ConfirmRequired);
        }
    }
    Ok(())
}

/// Runs a raw change inside the selected management recovery timer when required.
// NOT cancel-safe: cancellation may leave a write applied and its recovery timer armed.
pub(super) async fn run<T, Work>(
    server: &KccMcp,
    target: (&RouterId, &McpIdentity, bool),
    work: Work,
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<T, McpFailure>,
{
    let (host, identity, management) = target;
    let mut changes = server.begin_change(host, identity).await?;
    if !management {
        return work(&mut changes).await;
    }
    let info = server
        .registry
        .poll_info(host.as_str())
        .await
        .map_err(|_error| McpFailure::RouterUnreachable)?;
    let mode = match info.system_mode {
        Some(SystemMode::Router) => SafetyMode::Router,
        Some(_) | None => SafetyMode::ScheduledReboot,
    };
    let context: RouterCtx = server.router_ctx(host).await?;
    drop(
        SafetyNet::arm(&mut changes, &context, mode, 300)
            .await
            .map_err(map_workflow)?,
    );
    let applied = work(&mut changes).await;
    match SafetyNet::disarm(&mut changes, &context, mode).await {
        Ok(_result) => applied,
        Err(kcc_app::workflow::WorkflowError::Rci(RciError::Transport | RciError::Timeout)) => {
            applied
        }
        Err(error) => {
            drop(applied?);
            Err(map_workflow(error))
        }
    }
}
