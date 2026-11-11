//! Permission, confirmation and recovery for raw mutations.

use kcc_app::workflow::ChangeSet;
use kcc_catalog::Risk;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet, recovery},
};
use kcc_rci::capabilities::SystemMode;

use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers, support::errors::map_workflow,
};

/// Checks risk before router discovery, including the permission needed for recovery.
pub(crate) fn authorize(
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
        for &permission in SafetyNet::management_permissions() {
            authorize_routers(target.0, permission, core::slice::from_ref(target.1))?;
        }
        if !confirm {
            return Err(McpFailure::ConfirmRequired);
        }
    }
    Ok(())
}

/// Runs a raw change inside the selected management recovery timer when required.
// NOT cancel-safe: cancellation may leave a write applied and its recovery timer armed.
pub(crate) async fn run<T, Work>(
    server: &KccMcp,
    target: (&RouterId, &McpIdentity, bool),
    work: Work,
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<T, McpFailure>,
{
    run_completed(server, target, async |changes| {
        work(changes).await.map(|value| (value, true))
    })
    .await
}

/// Runs raw work with the application's successful-change fact.
// NOT cancel-safe: cancellation may leave a write applied and its recovery timer armed.
pub(crate) async fn run_completed<T, Work>(
    server: &KccMcp,
    target: (&RouterId, &McpIdentity, bool),
    work: Work,
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<(T, bool), McpFailure>,
{
    let (host, identity, management) = target;
    if management {
        for &permission in SafetyNet::management_permissions() {
            authorize_routers(identity, permission, core::slice::from_ref(host))?;
        }
    }
    let mut changes = server.begin_change(host, identity).await?;
    if !management {
        return work(&mut changes).await.map(|(value, _applied)| value);
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
    let completed = applied.as_ref().is_ok_and(|(_value, applied)| *applied);
    let disarm = SafetyNet::disarm(&mut changes, &context, mode)
        .await
        .map_err(map_workflow);
    recovery::finish_applied(applied, disarm, completed)
        .map(|(value, _applied)| value)
        .map_err(super::errors::map_recovery)
}
