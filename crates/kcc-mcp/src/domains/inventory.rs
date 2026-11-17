//! The domain tool inventory: a pure data table of tool names, toolsets, and descriptions.
// allow: SIZE_OK - pure data table, one row per registered domain tool.

use super::table::Area;

/// Read tools: area, name, toolset, description.
pub(crate) const READ_TOOLS: &[(Area, &str, &str, &str)] = &[
    (
        Area::System,
        "kcc_system_read",
        "core",
        "Read system identity, clock, NTP, mode, internet status, storage and schedules",
    ),
    (
        Area::Interfaces,
        "kcc_interfaces_read",
        "core",
        "Read interfaces, one interface, statistics or traffic history",
    ),
    (
        Area::Wifi,
        "kcc_wifi_read",
        "core",
        "Read Wi-Fi access points, radios and stations",
    ),
    (
        Area::Clients,
        "kcc_clients_read",
        "core",
        "Read connected and known clients",
    ),
    (
        Area::Routing,
        "kcc_routing_read",
        "core",
        "Read the IPv4 and IPv6 routing tables",
    ),
    (
        Area::Wan,
        "kcc_wan_read",
        "network-write",
        "Read internet connections",
    ),
    (
        Area::Mesh,
        "kcc_mesh_read",
        "network-write",
        "Read mesh members and associations",
    ),
    (
        Area::Dhcp,
        "kcc_dhcp_read",
        "network-write",
        "Read DHCP pools, static leases, bindings and neighbours",
    ),
    (
        Area::Segments,
        "kcc_segments_read",
        "network-write",
        "Read network segments",
    ),
    (
        Area::Policies,
        "kcc_policies_read",
        "network-write",
        "Read connection policies",
    ),
    (
        Area::Nat,
        "kcc_nat_read",
        "network-write",
        "Read port forwards, NAT interfaces and sessions",
    ),
    (
        Area::Firewall,
        "kcc_firewall_read",
        "network-write",
        "Read access lists and UPnP redirects",
    ),
    (
        Area::VpnClients,
        "kcc_vpn_clients_read",
        "vpn",
        "Read VPN client tunnels",
    ),
    (
        Area::VpnServers,
        "kcc_vpn_servers_read",
        "vpn",
        "Read VPN server configuration",
    ),
    (
        Area::Dns,
        "kcc_dns_read",
        "dns",
        "Read DNS proxy state and configuration",
    ),
    (
        Area::KeenDns,
        "kcc_keendns_read",
        "dns",
        "Read KeenDNS state",
    ),
    (
        Area::Diagnostics,
        "kcc_diagnostics_read",
        "system-admin",
        "Read the system log",
    ),
    (
        Area::RouterUsers,
        "kcc_router_users_read",
        "system-admin",
        "Read router login accounts",
    ),
    (
        Area::Services,
        "kcc_services_read",
        "system-admin",
        "Read router services",
    ),
    (
        Area::Components,
        "kcc_components_read",
        "system-admin",
        "Read installed and pending components",
    ),
];

/// Write tools: area, name, toolset, description.
pub(crate) const WRITE_TOOLS: &[(Area, &str, &str, &str)] = &[
    (
        Area::Interfaces,
        "kcc_interfaces_write",
        "network-write",
        "Change interface state, description or security level",
    ),
    (
        Area::Wan,
        "kcc_wan_write",
        "network-write",
        "Create, delete or change internet connections",
    ),
    (
        Area::Wifi,
        "kcc_wifi_write",
        "network-write",
        "Change Wi-Fi access point and radio settings",
    ),
    (
        Area::Mesh,
        "kcc_mesh_write",
        "network-write",
        "Acquire, update or reboot mesh members",
    ),
    (
        Area::Clients,
        "kcc_clients_write",
        "network-write",
        "Register clients and change their access and policies",
    ),
    (
        Area::Dhcp,
        "kcc_dhcp_write",
        "network-write",
        "Change DHCP pools and static leases",
    ),
    (
        Area::Segments,
        "kcc_segments_write",
        "network-write",
        "Create or delete network segments",
    ),
    (
        Area::Routing,
        "kcc_routing_write",
        "network-write",
        "Add or remove static routes",
    ),
    (
        Area::Policies,
        "kcc_policies_write",
        "network-write",
        "Change connection policies",
    ),
    (
        Area::Nat,
        "kcc_nat_write",
        "network-write",
        "Add or remove port forwards and NAT interfaces",
    ),
    (
        Area::Firewall,
        "kcc_firewall_write",
        "network-write",
        "Change access-list rules and bindings",
    ),
    (
        Area::VpnClients,
        "kcc_vpn_clients_write",
        "vpn",
        "Create and configure VPN client tunnels",
    ),
    (
        Area::VpnServers,
        "kcc_vpn_servers_write",
        "vpn",
        "Configure VPN servers",
    ),
    (
        Area::Dns,
        "kcc_dns_write",
        "dns",
        "Change DNS proxy settings",
    ),
    (
        Area::KeenDns,
        "kcc_keendns_write",
        "dns",
        "Change KeenDNS names and remote access",
    ),
    (
        Area::System,
        "kcc_system_write",
        "system-admin",
        "Change system identity, clock and NTP; reboot or factory reset",
    ),
    (
        Area::Diagnostics,
        "kcc_diagnostics_write",
        "system-admin",
        "Start a diagnostic job (ping, traceroute, arping, iperf3)",
    ),
    (
        Area::RouterUsers,
        "kcc_router_users_write",
        "system-admin",
        "Create, tag, set the password of or delete router accounts",
    ),
    (
        Area::Services,
        "kcc_services_write",
        "system-admin",
        "Change router services and management listeners",
    ),
    (
        Area::Components,
        "kcc_components_write",
        "system-admin",
        "Queue component changes, set auto-update, commit",
    ),
    (
        Area::Storage,
        "kcc_storage_write",
        "system-admin",
        "Eject storage media",
    ),
    (
        Area::Schedules,
        "kcc_schedules_write",
        "system-admin",
        "Create schedules and set their actions",
    ),
    (
        Area::Logging,
        "kcc_logging_write",
        "system-admin",
        "Change log servers, reduction and suppression; clear the log",
    ),
];
