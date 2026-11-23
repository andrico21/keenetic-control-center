//! The domain tool inventory: one read and one write tool per curated area.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    DomainDescriptor, clients, components, dhcp, diagnostics, dns, firewall, interfaces, keendns,
    logging, mesh, nat, policies, router_users, routing, schedules, segments, services, storage,
    system, vpn_clients, vpn_servers, wan, wifi,
};

use super::{
    entware, entware_ssh,
    inventory::{READ_TOOLS, WRITE_TOOLS},
    read::read_ops,
    write::dispatch::write_ops,
};
use crate::registry::definitions::ToolDescription;

/// A curated area with MCP tools.
///
/// `internet`, `storage`, and `schedules` reads are merged into `kcc_system_read` (the
/// mandatory merge rule); `logging` reads duplicate `kcc_diagnostics_read`; the
/// configuration area is served by `kcc_config_state` and `kcc_config_save`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Area {
    /// System identity, clock, NTP, reboot; reads also cover internet, storage, schedules.
    System,
    /// Log and diagnostic jobs.
    Diagnostics,
    /// Connected clients.
    Clients,
    /// DHCP pools and leases.
    Dhcp,
    /// Network segments.
    Segments,
    /// Router login accounts.
    RouterUsers,
    /// Static routes.
    Routing,
    /// Connection policies.
    Policies,
    /// NAT and port forwarding.
    Nat,
    /// Access lists.
    Firewall,
    /// Router services.
    Services,
    /// Firmware components.
    Components,
    /// Attached storage maintenance.
    Storage,
    /// Schedules.
    Schedules,
    /// KeenDNS and remote access.
    KeenDns,
    /// Log configuration.
    Logging,
    /// DNS proxy.
    Dns,
    /// VPN client tunnels.
    VpnClients,
    /// VPN servers.
    VpnServers,
    /// Router interfaces.
    Interfaces,
    /// Internet connections.
    Wan,
    /// Wireless access points.
    Wifi,
    /// Mesh members.
    Mesh,
}

impl Area {
    /// The curated domain's descriptor.
    pub(crate) const fn descriptor(self) -> DomainDescriptor {
        match self {
            Self::System => system::DESCRIPTOR,
            Self::Diagnostics => diagnostics::DESCRIPTOR,
            Self::Clients => clients::DESCRIPTOR,
            Self::Dhcp => dhcp::DESCRIPTOR,
            Self::Segments => segments::DESCRIPTOR,
            Self::RouterUsers => router_users::DESCRIPTOR,
            Self::Routing => routing::descriptor::DESCRIPTOR,
            Self::Policies => policies::descriptor::DESCRIPTOR,
            Self::Nat => nat::descriptor::DESCRIPTOR,
            Self::Firewall => firewall::descriptor::DESCRIPTOR,
            Self::Services => services::DESCRIPTOR,
            Self::Components => components::DESCRIPTOR,
            Self::Storage => storage::DESCRIPTOR,
            Self::Schedules => schedules::DESCRIPTOR,
            Self::KeenDns => keendns::DESCRIPTOR,
            Self::Logging => logging::DESCRIPTOR,
            Self::Dns => dns::DESCRIPTOR,
            Self::VpnClients => vpn_clients::DESCRIPTOR,
            Self::VpnServers => vpn_servers::DESCRIPTOR,
            Self::Interfaces => interfaces::DESCRIPTOR,
            Self::Wan => wan::DESCRIPTOR,
            Self::Wifi => wifi::DESCRIPTOR,
            Self::Mesh => mesh::DESCRIPTOR,
        }
    }

    /// Permission and risk of the write operation `op`.
    pub(crate) fn write_meta(self, op: &str) -> Option<(Permission, Risk)> {
        self.descriptor()
            .write_ops
            .iter()
            .find(|operation| operation.name == op)
            .map(|operation| (operation.permission, operation.risk))
            .or_else(|| {
                UNLISTED_WRITES
                    .iter()
                    .find(|&&(area, name, _meta)| area == self && name == op)
                    .map(|&(_area, _name, meta)| meta)
            })
    }
}

/// Write operations the MCP tools run that the domain registry does not list: area,
/// name, and the permission and risk of their planner.
const UNLISTED_WRITES: &[(Area, &str, (Permission, Risk))] = &[(
    Area::Storage,
    "initialize",
    (Permission::Destructive, Risk::Destructive),
)];

/// Every domain tool description.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    let reads = READ_TOOLS
        .iter()
        .map(|&(area, name, toolset, description)| {
            ToolDescription::single(
                name,
                description,
                toolset,
                Permission::Read,
                (true, false, true),
            )
            .with_ops(read_ops(area).to_vec())
        });
    let writes = WRITE_TOOLS
        .iter()
        .map(|&(area, name, toolset, description)| {
            let ops = write_ops(area);
            let metas = ops
                .iter()
                .filter_map(|op| area.write_meta(op))
                .collect::<Vec<_>>();
            let permission = metas
                .iter()
                .map(|&(permission, _risk)| permission)
                .min()
                .unwrap_or(Permission::Write);
            let read_only = metas.iter().all(|&(_permission, risk)| risk == Risk::Read);
            let destructive = metas
                .iter()
                .any(|&(_permission, risk)| risk == Risk::Destructive);
            ToolDescription::single(
                name,
                description,
                toolset,
                permission,
                (read_only, destructive, false),
            )
            .with_ops(ops.to_vec())
        });
    reads
        .chain(writes)
        .chain(entware::descriptions())
        .chain(entware_ssh::descriptions())
        .collect()
}
