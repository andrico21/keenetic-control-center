//! Checks every SSH flow runs before it changes or contacts anything.

use kcc_app::{
    audit::ActorKind,
    entware_ssh::state::{EnrolmentState, SshEnrolment},
    permissions::Permission,
    registry,
};
use kcc_ssh::{error::SshError, grammar::RouterId, transport::AdmittedAddresses};

use super::{Caller, SshServices, error::EntwareError};
use crate::{RouterCtx, entware};

/// Refuses a caller whose role lacks `Permission::Destructive` on the router.
///
/// # Errors
/// [`EntwareError::PermissionDenied`].
pub(super) fn authorize(caller: &Caller<'_>) -> Result<(), EntwareError> {
    registry::authorize(caller.role, Permission::Destructive, caller.router)
        .map_err(|_denied| EntwareError::PermissionDenied)
}

/// [`authorize`], then refuses MCP callers: the enrolment steps that open SSH are
/// Web and CLI only, so the Entware password never travels through MCP.
///
/// # Errors
/// [`EntwareError::PermissionDenied`] or [`EntwareError::McpRefused`].
pub(super) fn authorize_enrolment(caller: &Caller<'_>) -> Result<(), EntwareError> {
    authorize(caller)?;
    if caller.actor.kind == ActorKind::Mcp {
        return Err(EntwareError::McpRefused);
    }
    Ok(())
}

/// Refuses while `opkg chroot` is on, read over RCI.
///
/// # Errors
/// [`EntwareError::ChrootEnabled`], or the read's [`EntwareError::Domain`].
// NOT cancel-safe: the settings read may sign in first (see `entware::read_settings`).
pub(super) async fn refuse_chroot(router: &RouterCtx) -> Result<(), EntwareError> {
    if entware::read_settings(router).await?.chroot {
        return Err(EntwareError::ChrootEnabled);
    }
    Ok(())
}

/// The host of the router URL the RCI client uses.
pub(super) fn current_host(router: &RouterCtx) -> String {
    router.client.router_url().host().unwrap_or_default()
}

/// The router's enrolment record, checked against the current router URL host.
///
/// A record whose `router_host` differs from the current host becomes Pending, loses its
/// pin and router host, and the step is refused: only a new probe and bootstrap pin a key
/// for the new host.
///
/// # Errors
/// [`EntwareError::RouterHostChanged`], or a state failure.
pub(super) fn checked_record(
    services: &SshServices,
    router: &RouterCtx,
    caller: &Caller<'_>,
) -> Result<Option<SshEnrolment>, EntwareError> {
    let Some(mut record) = services.store.load(caller.router)? else {
        return Ok(None);
    };
    let current = current_host(router);
    if record
        .router_host
        .as_deref()
        .is_some_and(|enrolled| enrolled != current)
    {
        record.state = EnrolmentState::Pending;
        record.router_host = None;
        record.host_key = None;
        record.fingerprint = None;
        services.store.save(caller.router, &record)?;
        tracing::warn!(
            router = caller.router,
            "router URL host changed; Entware SSH pin cleared"
        );
        return Err(EntwareError::RouterHostChanged);
    }
    Ok(Some(record))
}

/// The router's addresses the outbound policy admits for SSH on `port`.
///
/// # Errors
/// [`SshError::NotAdmitted`].
// cancel-safe: dropped, it abandons a DNS lookup; nothing is dialled.
pub(super) async fn admit(
    services: &SshServices,
    router: &RouterCtx,
    port: u16,
) -> Result<AdmittedAddresses, SshError> {
    AdmittedAddresses::admit(
        services.registry.outbound(),
        router.client.router_url(),
        port,
    )
    .await
}

/// The router id in `kcc-ssh`'s grammar.
///
/// # Errors
/// [`SshError::InvalidArgument`].
pub(super) fn router_id(caller: &Caller<'_>) -> Result<RouterId, SshError> {
    RouterId::parse(caller.router)
}
