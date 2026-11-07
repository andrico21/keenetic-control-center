//! `kcc_<area>_read`: typed reads through the curated domain readers.

use kcc_app::permissions::Permission;
use kcc_domain::{
    DomainError, RouterCtx, clients, components, dhcp, diagnostics, dns, firewall, interfaces,
    internet, keendns, mesh, nat, policies, router_users, routing, schedules, segments, services,
    storage, system, vpn_clients, vpn_servers, wan, wifi,
};
use kcc_rci::ObjectName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::table::Area;
use crate::{
    KccMcp, McpFailure,
    support::{errors::map_domain, route::parse},
};

/// Arguments of every read tool; `op` is restricted per tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadInput {
    /// Router profile id.
    host: String,
    /// Read operation.
    op: String,
    /// Object name for `get` and `access_point`.
    #[serde(default)]
    name: Option<String>,
    /// Session offset for `sessions`.
    #[serde(default)]
    offset: Option<u32>,
    /// Log lines for `system_log`, 1 to 1000 (default 100).
    #[serde(default)]
    max_lines: Option<u32>,
}

/// Read operations of `area`.
pub(crate) const fn read_ops(area: Area) -> &'static [&'static str] {
    match area {
        Area::System => &[
            "version",
            "system",
            "clock_date",
            "ntp_status",
            "system_mode",
            "internet_status",
            "ping_check",
            "storage_media",
            "storage_usb",
            "schedules",
        ],
        Area::Diagnostics => &["system_log"],
        Area::Clients | Area::RouterUsers | Area::Policies | Area::Services => &["list"],
        Area::Dhcp => &["pools", "static_leases", "bindings", "neighbours"],
        Area::Segments => &["read_segments"],
        Area::Routing => &["ipv4_routes", "ipv6_routes"],
        Area::Nat => &["forwards", "interfaces", "sessions"],
        Area::Firewall => &["access_lists", "upnp_redirects"],
        Area::Components => &["list", "pending"],
        Area::KeenDns => &["status"],
        Area::Dns => &["dns_proxy", "running_configuration"],
        Area::VpnClients => &["interfaces"],
        Area::VpnServers => &["configuration"],
        Area::Interfaces => &["list", "get", "statistics", "traffic_history"],
        Area::Wan => &["connections"],
        Area::Wifi => &["access_point", "radios", "stations"],
        Area::Mesh => &["members", "associations"],
        Area::Storage | Area::Schedules | Area::Logging => &[],
    }
}

/// Serializes one domain read.
fn json<T>(result: Result<T, DomainError>) -> Result<Value, McpFailure>
where
    T: Serialize,
{
    let value = result.map_err(map_domain)?;
    serde_json::to_value(value).map_err(|_error| McpFailure::Internal)
}

/// Parses the `name` selector.
fn name(input: &ReadInput) -> Result<ObjectName, McpFailure> {
    input
        .name
        .as_deref()
        .ok_or(McpFailure::InvalidArguments)?
        .parse()
        .map_err(|_error| McpFailure::InvalidArguments)
}

/// Runs one read tool call.
pub(crate) async fn read(
    server: &KccMcp,
    area: Area,
    arguments: Value,
) -> Result<Value, McpFailure> {
    let input: ReadInput = parse(arguments)?;
    if !read_ops(area).contains(&input.op.as_str()) {
        return Err(McpFailure::InvalidArguments);
    }
    if input
        .max_lines
        .is_some_and(|lines| !(1..=1000).contains(&lines))
    {
        return Err(McpFailure::InvalidArguments);
    }
    let (_identity, host) = server.authorize_host(Permission::Read, input.host.clone())?;
    let ctx = server.router_ctx(&host).await?;
    let value = dispatch(&ctx, area, &input).await?;
    Ok(serde_json::json!({ "op": input.op, "value": value }))
}

/// Calls the curated reader of `area` and `input.op`.
async fn dispatch(ctx: &RouterCtx, area: Area, input: &ReadInput) -> Result<Value, McpFailure> {
    match area {
        Area::System => system_read(ctx, &input.op).await,
        Area::Diagnostics => {
            json(diagnostics::read_log(&ctx.client, input.max_lines.unwrap_or(100)).await)
        }
        Area::Clients => json(clients::read_clients(ctx).await),
        Area::RouterUsers => json(router_users::read_users(ctx).await),
        Area::Policies => json(policies::read::policies(ctx).await),
        Area::Services => json(services::read_services(ctx).await),
        Area::Components if input.op == "list" => json(components::read_components(ctx).await),
        Area::Components => json(components::read_pending(ctx).await),
        Area::KeenDns => json(keendns::read_status(ctx).await),
        Area::Dns if input.op == "dns_proxy" => json(dns::read_dns_proxy(ctx).await),
        Area::Dns => json(dns::read_configuration(ctx).await),
        Area::VpnClients => json(vpn_clients::read_clients(ctx).await),
        Area::VpnServers => json(vpn_servers::read_servers(ctx).await),
        Area::Dhcp
        | Area::Segments
        | Area::Routing
        | Area::Nat
        | Area::Firewall
        | Area::Interfaces
        | Area::Wan
        | Area::Wifi
        | Area::Mesh => network_read(ctx, area, input).await,
        Area::Storage | Area::Schedules | Area::Logging => Err(McpFailure::InvalidArguments),
    }
}

/// System reads, including the merged internet, storage, and schedule reads.
async fn system_read(ctx: &RouterCtx, op: &str) -> Result<Value, McpFailure> {
    match op {
        "version" => json(system::read_version(ctx).await),
        "system" => json(system::read_system(ctx).await),
        "clock_date" => json(system::read_clock_date(ctx).await),
        "ntp_status" => json(system::read_ntp_status(ctx).await),
        "system_mode" => json(system::read_system_mode(ctx).await),
        "internet_status" => json(internet::read_status(ctx).await),
        "ping_check" => json(internet::read_ping_check(ctx).await),
        "storage_media" => json(storage::read_media(ctx).await),
        "storage_usb" => json(storage::read_usb(ctx).await),
        _ => json(schedules::read_schedules(ctx).await),
    }
}

/// Network-area reads.
async fn network_read(ctx: &RouterCtx, area: Area, input: &ReadInput) -> Result<Value, McpFailure> {
    match (area, input.op.as_str()) {
        (Area::Dhcp, "pools") => json(dhcp::read_pools(ctx).await),
        (Area::Dhcp, "static_leases") => json(dhcp::read_static_leases(ctx).await),
        (Area::Dhcp, "bindings") => json(dhcp::read_bindings(ctx).await),
        (Area::Dhcp, _) => json(dhcp::read_neighbours(ctx).await),
        (Area::Segments, _) => json(segments::read_segments(ctx).await),
        (Area::Routing, "ipv4_routes") => json(routing::read::ipv4_table(ctx).await),
        (Area::Routing, _) => json(routing::read::ipv6_table(ctx).await),
        (Area::Nat, "forwards") => json(nat::read::running_forwards(ctx).await),
        (Area::Nat, "interfaces") => json(nat::read::interfaces(ctx).await),
        (Area::Nat, _) => {
            let offset = usize::try_from(input.offset.unwrap_or(0))
                .map_err(|_error| McpFailure::InvalidArguments)?;
            let page = nat::read::sessions_page(ctx, offset)
                .await
                .map_err(map_domain)?;
            Ok(serde_json::json!({ "offset": page.offset, "rows": page.rows }))
        }
        (Area::Firewall, "access_lists") => json(firewall::read::access_lists(ctx).await),
        (Area::Firewall, _) => json(firewall::read::upnp_redirects(ctx).await),
        (Area::Interfaces, "list") => json(interfaces::read_interfaces(ctx).await),
        (Area::Interfaces, "get") => json(interfaces::read_interface(ctx, &name(input)?).await),
        (Area::Interfaces, "statistics") => json(interfaces::read_statistics(ctx).await),
        (Area::Interfaces, _) => json(interfaces::read_traffic_history(ctx).await),
        (Area::Wan, _) => json(wan::read_connections(ctx).await),
        (Area::Wifi, "access_point") => json(wifi::read_access_point(ctx, &name(input)?).await),
        (Area::Wifi, "radios") => json(wifi::read_radios(ctx).await),
        (Area::Wifi, _) => json(wifi::read_stations(ctx).await),
        (Area::Mesh, "members") => json(mesh::read_members(ctx).await),
        (Area::Mesh, _) => json(mesh::read_associations(ctx).await),
        (
            Area::System
            | Area::Diagnostics
            | Area::Clients
            | Area::RouterUsers
            | Area::Policies
            | Area::Services
            | Area::Components
            | Area::KeenDns
            | Area::Dns
            | Area::VpnClients
            | Area::VpnServers
            | Area::Storage
            | Area::Schedules
            | Area::Logging,
            _,
        ) => Err(McpFailure::InvalidArguments),
    }
}
