//! Shared steps of every write tool: operation check, authorization, risk confirmation,
//! argument extraction, and protected application.

use core::net::Ipv4Addr;

use kcc_app::workflow::{ChangeSet, CliChangeRequest};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, RouterCtx};
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    KccMcp, McpFailure, McpIdentity, RouterId,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        validate::valid_text,
    },
};

/// An authorized write target: caller, router, and domain context.
pub(super) type Opened = (McpIdentity, RouterId, RouterCtx);

/// Longest free-text write value.
const MAX_VALUE_CHARS: usize = 256;

/// Refuses an operation outside the tool's `op` enum.
pub(super) fn check_op(ops: &[&str], op: &str) -> Result<(), McpFailure> {
    if ops.contains(&op) {
        Ok(())
    } else {
        Err(McpFailure::InvalidArguments)
    }
}

/// Authorizes the operation's permission and risk on `host` and opens its domain context.
pub(super) async fn open(
    server: &KccMcp,
    area: Area,
    request: (String, &str, bool),
) -> Result<Opened, McpFailure> {
    let (host, op, confirm) = request;
    let (permission, risk) = area.write_meta(op).ok_or(McpFailure::InvalidArguments)?;
    let (identity, router) = server.authorize_host(permission, host)?;
    confirm_risk(server, risk, confirm)?;
    let ctx = server.router_ctx(&router).await?;
    Ok((identity, router, ctx))
}

/// Requires `confirm` for management changes, and the server switch for destructive ones.
pub(super) fn confirm_risk(server: &KccMcp, risk: Risk, confirm: bool) -> Result<(), McpFailure> {
    server.require_destructive(risk, confirm)?;
    if risk >= Risk::Management && !confirm {
        return Err(McpFailure::Forbidden);
    }
    Ok(())
}

/// Opens the protected change set of an opened target.
pub(super) async fn begin(server: &KccMcp, opened: &Opened) -> Result<ChangeSet, McpFailure> {
    let (identity, router, _ctx) = opened;
    server.begin_change(router, identity).await
}

/// Applies a planned CLI operation after confirming its planned risk.
pub(super) async fn apply_cli<F>(
    server: &KccMcp,
    opened: &Opened,
    planned: (Result<ChangeOp, DomainError>, bool, F),
) -> Result<Value, McpFailure>
where
    F: FnOnce(&ChangeOp) -> Result<CliChangeRequest, DomainError>,
{
    let (operation, confirm, convert) = planned;
    let operation = operation.map_err(map_domain)?;
    confirm_risk(server, operation.risk, confirm)?;
    let request = convert(&operation).map_err(map_domain)?;
    let mut changes = begin(server, opened).await?;
    let result = changes.apply_cli(request).await.map_err(map_workflow)?;
    Ok(applied(result.unsaved))
}

/// The result of an applied, unsaved change.
pub(super) fn applied(unsaved: bool) -> Value {
    json!({ "applied": true, "unsaved": unsaved })
}

/// A required object name.
pub(super) fn object(value: Option<&str>) -> Result<ObjectName, McpFailure> {
    value
        .ok_or(McpFailure::InvalidArguments)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// A required bounded text value.
pub(super) fn text(value: Option<&str>) -> Result<&str, McpFailure> {
    let text = value.ok_or(McpFailure::InvalidArguments)?;
    valid_text(text, MAX_VALUE_CHARS)?;
    Ok(text)
}

/// A required argument.
pub(super) fn needed<T>(value: Option<T>) -> Result<T, McpFailure> {
    value.ok_or(McpFailure::InvalidArguments)
}

/// A required IPv4 address.
pub(super) fn ipv4(value: Option<&str>) -> Result<Ipv4Addr, McpFailure> {
    text(value)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// A required secret, moved without copying into ordinary strings.
pub(super) fn secret(value: Option<SecretString>) -> Result<SecretString, McpFailure> {
    value.ok_or(McpFailure::InvalidArguments)
}
