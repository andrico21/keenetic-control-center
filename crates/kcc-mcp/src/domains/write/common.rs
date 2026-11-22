//! Shared steps of every write tool: operation check, authorization, risk confirmation,
//! argument extraction, and protected application.

#[cfg(test)]
mod tests;

use core::{net::Ipv4Addr, slice::from_ref};

use kcc_app::{
    audit::receipt::{AuditReceipt, Pending},
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest},
};
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, DomainError, RouterCtx, configuration::SafetyNet,
    router_users::protection::OwnLogins, verification,
};
use kcc_rci::{Mac, ObjectName};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        raw_change,
        shape::noting,
        validate::valid_text,
    },
};

/// An authorized write target: caller, router, and domain context.
pub(super) type Opened = (McpIdentity, RouterId, RouterCtx);

/// Longest free-text write value.
const MAX_VALUE_CHARS: usize = 256;

/// Refuses an operation outside the tool's `op` enum.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn check_op(ops: &[&str], op: &str) -> Result<(), McpFailure> {
    if ops.contains(&op) {
        Ok(())
    } else {
        Err(McpFailure::InvalidArguments)
    }
}

/// Authorizes the operation's permission and risk on `host` and opens its domain context.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: context discovery can initialize the authenticated router session.
pub(super) async fn open(
    server: &KccMcp,
    area: Area,
    request: (String, &str, bool),
) -> Result<Opened, McpFailure> {
    let (host, op, confirm) = request;
    let meta = area.write_meta(op).ok_or(McpFailure::InvalidArguments)?;
    open_as(server, meta, (host, confirm)).await
}

/// Authorizes an operation of `permission` and `risk` on `host`, then opens its domain
/// context.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: context discovery can initialize the authenticated router session.
pub(super) async fn open_as(
    server: &KccMcp,
    meta: (Permission, Risk),
    request: (String, bool),
) -> Result<Opened, McpFailure> {
    let ((permission, risk), (host, confirm)) = (meta, request);
    let (identity, router) = server.authorize_host(permission, host)?;
    confirm_risk(server, risk, confirm)?;
    for needed in SafetyNet::required(permission, risk) {
        authorize_routers(&identity, needed, from_ref(&router))?;
    }
    let ctx = server.router_ctx(&router).await?;
    Ok((identity, router, ctx))
}

/// Requires `confirm` for management changes, and the server switch for destructive ones.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn confirm_risk(server: &KccMcp, risk: Risk, confirm: bool) -> Result<(), McpFailure> {
    server.require_destructive(risk, confirm)?;
    if risk >= Risk::Management && !confirm {
        return Err(McpFailure::ConfirmRequired);
    }
    Ok(())
}

/// Runs a terminal or multi-step domain executor using its registered operation metadata.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn apply_registered<T, Work>(
    server: &KccMcp,
    opened: &Opened,
    planned: (Area, &str, bool, Work),
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<T, McpFailure>,
{
    let (area, name, confirm, work) = planned;
    let (permission, risk) = area.write_meta(name).ok_or(McpFailure::InvalidArguments)?;
    let operation = ChangeOp::new(Vec::new(), Vec::new(), risk, permission, false);
    apply(server, opened, (&operation, confirm, work)).await
}

/// Hands ownership to executors whose recovery lifetime is a background job.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: change-set creation may complete before ownership reaches the executor.
pub(super) async fn begin(server: &KccMcp, opened: &Opened) -> Result<ChangeSet, McpFailure> {
    let (identity, router, _ctx) = opened;
    server.begin_change(router, identity).await
}

/// Checks the permissions of a management write before runtime classification can contact
/// a router.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn preauthorize_management(server: &KccMcp, host: &str) -> Result<(), McpFailure> {
    let (identity, router) = server.authorize_host(Permission::Write, host.to_owned())?;
    for permission in SafetyNet::required(Permission::Write, Risk::Management) {
        authorize_routers(&identity, permission, from_ref(&router))?;
    }
    Ok(())
}

/// Executes every planned curated mutation under its operation's risk and permissions.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn apply<T, Work>(
    server: &KccMcp,
    opened: &Opened,
    planned: (&ChangeOp, bool, Work),
) -> Result<T, McpFailure>
where
    Work: AsyncFnOnce(&mut ChangeSet) -> Result<T, McpFailure>,
{
    let (operation, confirm, work) = planned;
    confirm_risk(server, operation.risk, confirm)?;
    let (identity, router, _context) = opened;
    for permission in SafetyNet::required(operation.permission, operation.risk) {
        authorize_routers(identity, permission, from_ref(router))?;
    }
    raw_change::run(
        server,
        (
            router,
            identity,
            (operation.risk == Risk::Management).then_some(operation.permission),
        ),
        work,
    )
    .await
}

/// Applies a planned CLI operation after confirming its planned risk.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: a transmitted change may apply before read-back or timer cleanup.
pub(super) async fn apply_cli<F>(
    server: &KccMcp,
    opened: &Opened,
    planned: (Result<ChangeOp, DomainError>, bool, F),
) -> Result<Value, McpFailure>
where
    F: FnOnce(&ChangeOp) -> Result<CliChangeRequest, DomainError>,
{
    let (planning, confirm, convert) = planned;
    let operation = planning.map_err(map_domain)?;
    confirm_risk(server, operation.risk, confirm)?;
    let request =
        verification::complete(convert(&operation).map_err(map_domain)?).map_err(map_domain)?;
    verification::require(&request).map_err(map_domain)?;
    let (identity, router, _context) = opened;
    authorize_routers(identity, request.permission, from_ref(router))?;
    let result = apply(
        server,
        opened,
        (&operation, confirm, async |changes| {
            changes.apply_cli(request).await.map_err(map_workflow)
        }),
    )
    .await?;
    Ok(applied(result.unsaved, &result.audit))
}

/// The result of an applied change, marked `audit_pending` while its entry is queued.
pub(super) fn applied(unsaved: bool, audit: &AuditReceipt) -> Value {
    noting(json!({ "applied": true, "unsaved": unsaved }), audit)
}

/// `value`, marked `audit_pending` while one of the `queued` entries of a multi-step
/// change is still queued.
pub(super) fn noting_queued(value: Value, queued: Vec<Pending>) -> Value {
    queued.into_iter().fold(value, |noted, pending| {
        noting(noted, &AuditReceipt::Pending(pending))
    })
}

/// The router accounts kcc signs in to `router` with, which account changes must keep.
///
/// # Errors
///
/// Forbidden when the profile names no login, internal when it cannot be read.
pub(super) fn own_logins(server: &KccMcp, router: &str) -> Result<OwnLogins, McpFailure> {
    let profile = server
        .registry
        .get(router)
        .map_err(|_error| McpFailure::Internal)?
        .profile;
    OwnLogins::new(&profile.login, profile.read_login.as_deref()).map_err(map_domain)
}

/// A required object name.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn object(value: Option<&str>) -> Result<ObjectName, McpFailure> {
    value
        .ok_or(McpFailure::InvalidArguments)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// A required MAC address.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn mac(value: Option<&str>) -> Result<Mac, McpFailure> {
    text(value)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// A required bounded text value.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn text(value: Option<&str>) -> Result<&str, McpFailure> {
    let text = value.ok_or(McpFailure::InvalidArguments)?;
    valid_text(text, MAX_VALUE_CHARS)?;
    Ok(text)
}

/// A required argument.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn needed<T>(value: Option<T>) -> Result<T, McpFailure> {
    value.ok_or(McpFailure::InvalidArguments)
}

/// A required IPv4 address.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn ipv4(value: Option<&str>) -> Result<Ipv4Addr, McpFailure> {
    text(value)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// A required secret, moved without copying into ordinary strings.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(super) fn secret(value: Option<SecretString>) -> Result<SecretString, McpFailure> {
    value.ok_or(McpFailure::InvalidArguments)
}
