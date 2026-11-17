//! Permission, confirmation and recovery for raw mutations.

use core::slice::from_ref;

use kcc_app::{permissions::Permission, workflow::ChangeSet};
use kcc_catalog::Risk;
use kcc_domain::configuration::{SafetyMode, SafetyNet, bracket};

use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers, support::errors::map_recovery,
};

/// Checks a raw change of `risk` before router discovery: the server switch and
/// confirmation for management and destructive changes, then the change's permissions.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
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
    for permission in SafetyNet::required(Permission::RawRci, risk) {
        authorize_routers(target.0, permission, from_ref(target.1))?;
    }
    Ok(())
}

/// Runs a change, inside the router's recovery timer when `target.2` names the permission
/// of a management change.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: cancellation may leave a write applied and its recovery timer armed.
pub(crate) async fn run<T, Work>(
    server: &KccMcp,
    target: (&RouterId, &McpIdentity, Option<Permission>),
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

/// Runs a change whose work also reports whether at least one change item applied.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: cancellation may leave a write applied and its recovery timer armed.
pub(crate) async fn run_completed<T, Work>(
    server: &KccMcp,
    target: (&RouterId, &McpIdentity, Option<Permission>),
    work: Work,
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<(T, bool), McpFailure>,
{
    let (host, identity, management) = target;
    let mut changes = server.begin_change(host, identity).await?;
    let Some(permission) = management else {
        return work(&mut changes).await.map(|(value, _applied)| value);
    };
    let mode =
        SafetyMode::for_change(&changes).map_err(|_unknown| McpFailure::RouterModeUnknown)?;
    let context = server.router_ctx(host).await?;
    bracket::guarded(
        &mut changes,
        &context,
        mode,
        permission,
        || true,
        async |open, _router| work(open).await,
    )
    .await
    .map_err(map_recovery)
}
