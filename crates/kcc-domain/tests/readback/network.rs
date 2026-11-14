//! Read-back rows of the mesh, WAN and VPN-server domains.

use core::net::Ipv4Addr;

use kcc_domain::{
    RouterCtx,
    interfaces::ManagementVerdict,
    mesh,
    vpn_servers::{self, VpnServerChange, VpnServerService},
    wan,
};
use kcc_testkit::model::Firmware;

use super::model::{Check, Expect, Field, Row, Step, Steps};
use crate::support::{TestResult, refused_by_catalog};

/// The mesh, WAN and VPN-server rows.
pub(crate) const ROWS: &[Row] = &[
    Row::new(
        "mesh.silent_acquisition",
        mesh_acquire,
        Expect::Silent {
            path: "parse",
            field: Field::Exact("show/mws/member"),
        },
    ),
    Row::new(
        "mesh.acquired_member",
        mesh_acquire,
        Expect::Saved {
            after: Some(member_listed),
        },
    ),
    Row::new(
        "wan.silent_create",
        wan_create,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("interface"),
        },
    ),
    Row::new(
        "wan.silent_addressing_and_delete",
        wan_addressing_and_delete,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("interface"),
        },
    ),
    Row::new(
        "vpn_servers.silent_service",
        vpn_service,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("service"),
        },
    ),
    Row::new(
        "vpn_servers.settings",
        vpn_settings,
        Expect::Saved { after: None },
    ),
    Row::new(
        "vpn_servers.crypto_map",
        crypto_map,
        Expect::Saved { after: None },
    ),
];

/// A mesh candidate acquisition.
fn mesh_acquire(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = mesh::plan_acquire(ctx, "candidate67")?;
        Ok(vec![Step::Cli(mesh::change_request(&operation)?)])
    })
}

/// The acquired candidate is in a fresh membership read.
fn member_listed(ctx: &RouterCtx) -> Check<'_> {
    Box::pin(async move {
        let members = mesh::read_members(ctx).await?;
        Ok(members
            .iter()
            .any(|member| member.id.as_deref() == Some("candidate67")))
    })
}

/// A WAN connection create.
fn wan_create(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let name = "Ethernet67".parse()?;
        let operation = wan::plan_create(ctx, &name).await?;
        Ok(vec![Step::Cli(wan::change_request(&name, &operation)?)])
    })
}

/// Delete, DHCP and static addressing of one connection.
fn wan_addressing_and_delete(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let name = "Bridge0".parse()?;
        let operations = [
            wan::plan_delete(ctx, &name).await?,
            wan::plan_dhcp(ctx, &name, ManagementVerdict::NotManagement)?,
            wan::plan_static_address(
                ctx,
                &name,
                wan::StaticAddress::new(
                    Ipv4Addr::new(192, 0, 2, 67),
                    Ipv4Addr::new(255, 255, 255, 0),
                ),
                ManagementVerdict::NotManagement,
            )?,
        ];
        let mut steps = Vec::new();
        for operation in &operations {
            steps.push(Step::Cli(wan::change_request(&name, operation)?));
        }
        Ok(steps)
    })
}

/// Plans each change and returns the CLI writes.
fn plan_all(ctx: &RouterCtx, changes: &[VpnServerChange]) -> TestResult<Vec<Step>> {
    let mut steps = Vec::new();
    for change in changes {
        let operation = vpn_servers::plan_change(ctx, change)?;
        steps.push(Step::Cli(vpn_servers::change_request(&operation)?));
    }
    Ok(steps)
}

/// The SSTP service activation.
fn vpn_service(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        plan_all(
            ctx,
            &[VpnServerChange::Service {
                service: VpnServerService::Sstp,
                enabled: true,
            }],
        )
    })
}

/// SSTP service, binding and pool settings.
fn vpn_settings(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        plan_all(
            ctx,
            &[
                VpnServerChange::Service {
                    service: VpnServerService::Sstp,
                    enabled: true,
                },
                VpnServerChange::SstpInterface {
                    interface: "Bridge0".to_owned(),
                },
                VpnServerChange::SstpPool {
                    begin: "192.0.2.67".to_owned(),
                    size: Some(5),
                },
            ],
        )
    })
}

/// A named IPsec map and its virtual-IP fields; 4.3.9 refuses the DNS servers.
fn crypto_map(ctx: &RouterCtx, firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let mut steps = Vec::new();
        for change in [
            VpnServerChange::IpsecMap {
                name: "map67".to_owned(),
            },
            VpnServerChange::IpsecVirtualIp {
                name: "map67".to_owned(),
                enabled: true,
            },
            VpnServerChange::IpsecVirtualIpPool {
                name: "map67".to_owned(),
                begin: "192.0.2.67".to_owned(),
                end: None,
                size: Some(5),
            },
            VpnServerChange::IpsecVirtualIpDns {
                name: "map67".to_owned(),
                primary: "192.0.2.1".to_owned(),
                secondary: None,
            },
        ] {
            let planned = vpn_servers::plan_change(ctx, &change);
            if firmware == Firmware::V4_3
                && matches!(
                    change,
                    VpnServerChange::IpsecVirtualIpDns {
                        name: _,
                        primary: _,
                        secondary: _
                    }
                )
            {
                // 4.3.9 documents no `crypto map virtual-ip dns-servers`.
                assert!(
                    refused_by_catalog(&planned),
                    "vpn_servers.crypto_map on {firmware:?}: {planned:?}"
                );
                continue;
            }
            steps.push(Step::Cli(vpn_servers::change_request(&planned?)?));
        }
        Ok(steps)
    })
}
