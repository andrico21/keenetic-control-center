//! `kcc_clients_write`, `kcc_dhcp_write`, and `kcc_segments_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    clients::{self, Access, PolicySelection},
    dhcp::{self, model::PoolConfig},
    segments::{self, SegmentError, SegmentSpec},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{
    Opened, applied, apply, check_op, ipv4, mac, needed, noting_queued, open, text,
};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
    },
};

/// Client write operations.
pub(super) const CLIENT_OPS: &[&str] = &[
    "register",
    "remove",
    "access",
    "schedule",
    "policy",
    "priority",
    "default_policy",
    "interface_policy",
    "wake",
];

/// DHCP write operations.
pub(super) const DHCP_OPS: &[&str] = &["pool", "static_lease"];

/// Segment write operations.
pub(super) const SEGMENT_OPS: &[&str] = &["create", "delete"];

/// Arguments of `kcc_clients_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Client MAC address.
    #[serde(default)]
    mac: Option<String>,
    /// Client name, schedule, or policy name.
    #[serde(default)]
    value: Option<String>,
    /// Interface for `interface_policy`.
    #[serde(default)]
    interface: Option<String>,
    /// Access override: `true` permits, `false` denies.
    #[serde(default)]
    permit: Option<bool>,
    /// Client priority.
    #[serde(default)]
    priority: Option<u8>,
}

/// Arguments of `kcc_dhcp_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DhcpInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Pool name.
    #[serde(default)]
    name: Option<String>,
    /// First pool address, or the lease address for `static_lease`.
    #[serde(default)]
    begin: Option<String>,
    /// Last pool address.
    #[serde(default)]
    end: Option<String>,
    /// Bound interface.
    #[serde(default)]
    interface: Option<String>,
    /// Whether the pool is enabled.
    #[serde(default)]
    enabled: Option<bool>,
    /// Client MAC for `static_lease`.
    #[serde(default)]
    mac: Option<String>,
}

/// Arguments of `kcc_segments_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SegmentInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Segment id.
    id: u16,
    /// VLAN id for `create`.
    #[serde(default)]
    vlan_id: Option<u16>,
    /// Segment IPv4 address for `create`.
    #[serde(default)]
    address: Option<String>,
    /// Segment IPv4 mask for `create`.
    #[serde(default)]
    mask: Option<String>,
    /// First DHCP address for `create`.
    #[serde(default)]
    dhcp_begin: Option<String>,
    /// Last DHCP address for `create`.
    #[serde(default)]
    dhcp_end: Option<String>,
    /// Switch ports joined to the segment.
    #[serde(default)]
    switch_ports: Vec<String>,
    /// Access point joined to the segment.
    #[serde(default)]
    access_point: Option<String>,
}

/// Plans one client change.
async fn plan_client(
    ctx: &RouterCtx,
    input: &ClientInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let client_mac = || text(input.mac.as_deref());
    let selection = || -> Result<PolicySelection<'_>, McpFailure> {
        Ok(match (input.permit, input.value.as_deref()) {
            (Some(true), _) => PolicySelection::Access(Access::Permit),
            (Some(false), _) => PolicySelection::Access(Access::Deny),
            (None, value) => PolicySelection::Policy(text(value)?),
        })
    };
    let op = input.op.as_str();
    if matches!(op, "access" | "schedule" | "policy" | "priority") {
        let client = clients::read_client(ctx, client_mac()?)
            .await
            .map_err(map_domain)?
            .ok_or(McpFailure::InvalidArguments)?;
        let name = input.value.as_deref().unwrap_or_default();
        return Ok(match op {
            "access" => {
                let access = if needed(input.permit)? {
                    Access::Permit
                } else {
                    Access::Deny
                };
                clients::plan_access(ctx, &client, name, access)
            }
            "schedule" => {
                clients::plan_schedule(ctx, &client, name, text(input.interface.as_deref())?)
            }
            "policy" => clients::plan_policy(ctx, &client, name, text(input.interface.as_deref())?),
            _ => clients::plan_priority(ctx, &client, name, needed(input.priority)?),
        });
    }
    Ok(match op {
        "register" => clients::plan_register(
            ctx,
            mac(input.mac.as_deref())?,
            text(input.value.as_deref())?,
        ),
        "remove" => clients::plan_remove(ctx, client_mac()?),
        "default_policy" => clients::plan_default_policy(ctx, selection()?),
        "interface_policy" => {
            clients::plan_interface_policy(ctx, text(input.interface.as_deref())?, selection()?)
        }
        _ => clients::plan_wake(ctx, client_mac()?),
    })
}

/// Applies a client or DHCP plan through the domain executor.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
async fn apply_planned(
    server: &KccMcp,
    opened: &Opened,
    planned: (ChangeOp, bool, Area),
) -> Result<Value, McpFailure> {
    let (operation, confirm, area) = planned;
    let result = apply(
        server,
        opened,
        (&operation, confirm, async |changes| {
            if area == Area::Dhcp {
                dhcp::apply(changes, &opened.2, &operation).await
            } else {
                clients::apply(changes, &opened.2, &operation).await
            }
            .map_err(map_workflow)
        }),
    )
    .await?;
    Ok(applied(result.unsaved, &result.audit))
}

/// Runs one client write. `schedule` and `policy` take the schedule or policy in
/// `interface` and the client's registration name in `value`.
pub(super) async fn clients(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: ClientInput = parse(arguments)?;
    check_op(CLIENT_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Clients,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let operation = plan_client(&opened.2, &input).await?.map_err(map_domain)?;
    apply_planned(server, &opened, (operation, input.confirm, Area::Clients)).await
}

/// Runs one DHCP write.
pub(super) async fn dhcp(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: DhcpInput = parse(arguments)?;
    check_op(DHCP_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Dhcp,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let ctx = &opened.2;
    let operation = if input.op == "pool" {
        let mut pool = PoolConfig::new(
            text(input.name.as_deref())?.to_owned(),
            ipv4(input.begin.as_deref())?,
            ipv4(input.end.as_deref())?,
        );
        pool.interface = input.interface.clone().unwrap_or_default();
        pool.enabled = input.enabled.unwrap_or(true);
        dhcp::plan_pool(ctx, &pool)
    } else {
        dhcp::plan_static_lease(
            ctx,
            mac(input.mac.as_deref())?,
            ipv4(input.begin.as_deref())?,
        )
        .await
    }
    .map_err(map_domain)?;
    apply_planned(server, &opened, (operation, input.confirm, Area::Dhcp)).await
}

/// Maps a multi-step segment failure.
fn map_segment(error: SegmentError) -> McpFailure {
    match error {
        SegmentError::Domain(domain) => map_domain(domain),
        SegmentError::StepFailed { step, source } => {
            tracing::warn!(step, error = ?source, "MCP segment step failed and was rolled back");
            map_workflow(*source)
        }
        SegmentError::RollbackFailed {
            step: _,
            rollback_step: _,
            source: _,
        }
        | _ => {
            tracing::error!(error = ?error, "MCP segment rollback failed");
            McpFailure::Internal
        }
    }
}

/// Runs one segment write through the stepwise segment executor.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn segments(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: SegmentInput = parse(arguments)?;
    check_op(SEGMENT_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Segments,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let ctx = &opened.2;
    if input.op == "create" {
        let mut spec = SegmentSpec::new(
            input.id,
            needed(input.vlan_id)?,
            ipv4(input.address.as_deref())?,
            ipv4(input.mask.as_deref())?,
            ipv4(input.dhcp_begin.as_deref())?,
            ipv4(input.dhcp_end.as_deref())?,
            input.switch_ports.clone(),
        );
        if let Some(access_point) = input.access_point.clone() {
            spec = spec.with_access_point(access_point);
        }
        let operation = segments::plan_create(ctx, &spec)
            .await
            .map_err(map_domain)?;
        let queued = apply(
            server,
            &opened,
            (&operation, input.confirm, async |changes| {
                drop(
                    segments::create(changes, ctx, &spec)
                        .await
                        .map_err(map_segment)?,
                );
                Ok(changes.queued_audit())
            }),
        )
        .await?;
        let reply = json!({ "applied": true, "unsaved": true, "id": input.id });
        return Ok(noting_queued(reply, queued));
    }
    let view = segments::read_segments(ctx)
        .await
        .map_err(map_domain)?
        .into_iter()
        .find(|segment| segment.id == input.id)
        .ok_or(McpFailure::InvalidArguments)?;
    let operation = view.deletion_plan(ctx).await.map_err(map_domain)?;
    let queued = apply(
        server,
        &opened,
        (&operation, input.confirm, async |changes| {
            drop(
                segments::delete_discovered(changes, ctx, &view)
                    .await
                    .map_err(map_segment)?,
            );
            Ok(changes.queued_audit())
        }),
    )
    .await?;
    let reply = json!({ "applied": true, "unsaved": true, "id": input.id });
    Ok(noting_queued(reply, queued))
}
