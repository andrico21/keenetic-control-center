//! One ignored test per kcc read; filter by name (`live_clients`, `live_dhcp_`, ...).

use core::time::Duration;

use kcc_domain::{
    RouterCtx, clients, components, dhcp, dns, entware, firewall, keendns, logging, mesh, nat,
    policies, router_users, routing, schedules, services, storage, system, vpn_servers, wifi,
};
use kcc_rci::{RciBody, RciPath};
use serde_json::json;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{capture::TestResult, decodes};

/// Lines the log read asks for, as the Web log page's poller does.
const LOG_LINES: u32 = 200;

/// Longest replay of the diagnostics ping.
const PING_BOUND: Duration = Duration::from_secs(30);

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_clients() -> TestResult {
    decodes(async |router: &RouterCtx| clients::read_clients(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_dhcp_bindings() -> TestResult {
    decodes(async |router: &RouterCtx| dhcp::read_bindings(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_dhcp_neighbours() -> TestResult {
    decodes(async |router: &RouterCtx| dhcp::read_neighbours(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_dhcp_static_leases() -> TestResult {
    decodes(async |router: &RouterCtx| dhcp::read_static_leases(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_dhcp_pools() -> TestResult {
    decodes(async |router: &RouterCtx| dhcp::read_pools(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_wifi_access_points() -> TestResult {
    decodes(async |router: &RouterCtx| wifi::read_access_points(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_wifi_radios() -> TestResult {
    decodes(async |router: &RouterCtx| wifi::read_radios(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_wifi_stations() -> TestResult {
    decodes(async |router: &RouterCtx| wifi::read_stations(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_mesh_members() -> TestResult {
    decodes(async |router: &RouterCtx| mesh::read_members(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_mesh_associations() -> TestResult {
    decodes(async |router: &RouterCtx| mesh::read_associations(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_routing_ipv4() -> TestResult {
    decodes(async |router: &RouterCtx| routing::read::ipv4_table(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_routing_ipv6() -> TestResult {
    decodes(async |router: &RouterCtx| routing::read::ipv6_table(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_routing_policies() -> TestResult {
    decodes(async |router: &RouterCtx| policies::read::policies(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_nat_sessions() -> TestResult {
    decodes(async |router: &RouterCtx| nat::read::sessions_page(router, 0).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_firewall_upnp() -> TestResult {
    decodes(async |router: &RouterCtx| firewall::read::upnp_redirects(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_storage_media() -> TestResult {
    decodes(async |router: &RouterCtx| storage::read_media(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_storage_usb() -> TestResult {
    decodes(async |router: &RouterCtx| storage::read_usb(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_system_schedules() -> TestResult {
    decodes(async |router: &RouterCtx| schedules::read_schedules(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_system_keendns() -> TestResult {
    decodes(async |router: &RouterCtx| keendns::read_status(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_system_users() -> TestResult {
    decodes(async |router: &RouterCtx| router_users::read_users(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_system_services() -> TestResult {
    decodes(async |router: &RouterCtx| services::read_services(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_system_version() -> TestResult {
    decodes(async |router: &RouterCtx| system::read_version(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_components_list() -> TestResult {
    decodes(async |router: &RouterCtx| components::read_components(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_components_pending() -> TestResult {
    decodes(async |router: &RouterCtx| components::read_pending(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_entware_status() -> TestResult {
    decodes(async |router: &RouterCtx| entware::read_status(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_log() -> TestResult {
    decodes(async |router: &RouterCtx| logging::read_log(router, LOG_LINES).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_vpn_servers() -> TestResult {
    decodes(async |router: &RouterCtx| vpn_servers::read_servers(router).await).await
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_dns_configuration() -> TestResult {
    decodes(async |router: &RouterCtx| dns::read_configuration(router).await).await
}

/// Starts `tools ping` and polls it against the captured chunks.
async fn ping(router: &RouterCtx) -> TestResult<RciBody> {
    let path = RciPath::from_segments(["tools", "ping"])?;
    let handle = router
        .client
        .start(path, &json!({"host": "192.0.2.1", "count": 2_u8}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    Ok(timeout(PING_BOUND, handle.poll(&CancellationToken::new())).await??)
}

#[tokio::test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
async fn live_diagnostics_ping() -> TestResult {
    decodes(ping).await
}
