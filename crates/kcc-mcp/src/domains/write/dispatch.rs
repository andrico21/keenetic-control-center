//! Per-area dispatch of the write tools: operation inventories, schemas, and handlers.

use alloc::sync::Arc;

use rmcp::model::JsonObject;
use serde_json::Value;

use super::{
    clients, dns, filtering, housekeeping, housekeeping::Chore, interfaces, jobs, routing,
    services, system, vpn, vpn_servers, wifi,
};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::route::{Progress, schema_with_ops},
};

/// Write operations of `area` that the MCP surface implements.
pub(crate) const fn write_ops(area: Area) -> &'static [&'static str] {
    match area {
        Area::System => system::OPS,
        Area::Diagnostics => jobs::DIAGNOSTIC_OPS,
        Area::Components => jobs::COMPONENT_OPS,
        Area::Clients => clients::CLIENT_OPS,
        Area::Dhcp => clients::DHCP_OPS,
        Area::Segments => clients::SEGMENT_OPS,
        Area::RouterUsers => services::USER_OPS,
        Area::Services => services::SERVICE_OPS,
        Area::KeenDns => services::KEENDNS_OPS,
        Area::Routing => routing::ROUTING_OPS,
        Area::Policies => routing::POLICY_OPS,
        Area::Nat => filtering::NAT_OPS,
        Area::Firewall => filtering::FIREWALL_OPS,
        Area::Storage => housekeeping::STORAGE_OPS,
        Area::Schedules => housekeeping::SCHEDULE_OPS,
        Area::Logging => housekeeping::LOGGING_OPS,
        Area::Dns => dns::DNS_OPS,
        Area::VpnClients => vpn::CLIENT_OPS,
        Area::VpnServers => vpn_servers::OPS,
        Area::Interfaces => interfaces::INTERFACE_OPS,
        Area::Wan => interfaces::WAN_OPS,
        Area::Wifi => wifi::WIFI_OPS,
        Area::Mesh => wifi::MESH_OPS,
    }
}

/// The input schema of `area`'s write tool.
pub(crate) fn schema(area: Area) -> Arc<JsonObject> {
    let ops = write_ops(area);
    match area {
        Area::System => schema_with_ops::<system::Input>(ops),
        Area::Diagnostics | Area::Components => schema_with_ops::<jobs::JobInput>(ops),
        Area::Clients => schema_with_ops::<clients::ClientInput>(ops),
        Area::Dhcp => schema_with_ops::<clients::DhcpInput>(ops),
        Area::Segments => schema_with_ops::<clients::SegmentInput>(ops),
        Area::RouterUsers | Area::Services | Area::KeenDns => {
            schema_with_ops::<services::AdminInput>(ops)
        }
        Area::Routing => schema_with_ops::<routing::RouteInput>(ops),
        Area::Policies => schema_with_ops::<routing::PolicyInput>(ops),
        Area::Nat => schema_with_ops::<filtering::NatInput>(ops),
        Area::Firewall => schema_with_ops::<filtering::FirewallInput>(ops),
        Area::Storage | Area::Schedules | Area::Logging => {
            schema_with_ops::<housekeeping::HousekeepingInput>(ops)
        }
        Area::Dns => schema_with_ops::<dns::DnsInput>(ops),
        Area::VpnClients => schema_with_ops::<vpn::VpnInput>(ops),
        Area::VpnServers => schema_with_ops::<vpn_servers::VpnServerInput>(ops),
        Area::Interfaces => schema_with_ops::<interfaces::InterfaceInput>(ops),
        Area::Wan => schema_with_ops::<interfaces::WanInput>(ops),
        Area::Wifi => schema_with_ops::<wifi::WifiInput>(ops),
        Area::Mesh => schema_with_ops::<wifi::MeshInput>(ops),
    }
}

/// Runs one write tool call.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it awaits the area's write handler; dropped mid-way, a router change may be
// applied without its read-back, audit receipt or timer cleanup.
pub(crate) async fn write(
    server: &KccMcp,
    area: Area,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    match area {
        Area::System => system::write(server, arguments).await,
        Area::Diagnostics => jobs::diagnostics(server, arguments, progress).await,
        Area::Components => jobs::components(server, arguments, progress).await,
        Area::Clients => clients::clients(server, arguments).await,
        Area::Dhcp => clients::dhcp(server, arguments).await,
        Area::Segments => clients::segments(server, arguments).await,
        Area::RouterUsers => services::router_users(server, arguments).await,
        Area::Services | Area::KeenDns => {
            services::services_or_keendns(server, area, arguments).await
        }
        Area::Routing => routing::routing(server, arguments).await,
        Area::Policies => routing::policies(server, arguments).await,
        Area::Nat => filtering::nat(server, arguments).await,
        Area::Firewall => filtering::firewall(server, arguments).await,
        Area::Storage => housekeeping::housekeeping(server, Chore::Storage, arguments).await,
        Area::Schedules => housekeeping::housekeeping(server, Chore::Schedules, arguments).await,
        Area::Logging => housekeeping::housekeeping(server, Chore::Logging, arguments).await,
        Area::Dns => dns::dns(server, arguments).await,
        Area::VpnClients => vpn::clients(server, arguments).await,
        Area::VpnServers => vpn_servers::servers(server, arguments).await,
        Area::Interfaces => interfaces::interfaces(server, arguments).await,
        Area::Wan => interfaces::wan(server, arguments).await,
        Area::Wifi => wifi::wifi(server, arguments).await,
        Area::Mesh => wifi::mesh(server, arguments).await,
    }
}
