//! The VPN servers tab: the PPTP/L2TP, SSTP and OpenConnect servers, IPsec/IKEv2, the
//! WireGuard server interfaces, and where users get their access.

use kcc_domain::vpn_servers::{ServerConfigStatus, VpnServerStatus};
use kcc_i18n::{bundle::tr, keys};
use serde_json::Value;

use super::{
    cells::Act,
    flow::Viewer,
    region::{Panel, Region},
    vpn_forms::Server,
    vpn_read::shown,
    vpn_tabs::{state, with_query},
};

/// Whether the router service `name` is on.
fn running(status: &VpnServerStatus, name: &str) -> bool {
    status
        .services
        .iter()
        .any(|service| service.name.as_deref() == Some(name) && service.enabled != Some(false))
}

/// The Enable or Disable action of the service `service`.
fn toggle(viewer: &Viewer, (service, on): (&str, bool)) -> Act {
    let (label, next) = if on {
        (keys::WEB_VPN_SERVER_DISABLE, "off")
    } else {
        (keys::WEB_VPN_SERVER_ENABLE, "on")
    };
    let fields = vec![
        ("service", service.to_owned()),
        ("enabled", next.to_owned()),
    ];
    Act::post(viewer.locale(), label, (viewer.href("vpn/service"), fields))
}

/// The panel of a server with an address pool and DNS servers.
fn server_panel(
    server: Server,
    (config, on): (&ServerConfigStatus, bool),
    viewer: &Viewer,
) -> Panel {
    let locale = viewer.locale();
    let operation = match server {
        Server::Vpn => ("vpn_pool", "vpn_service"),
        Server::Sstp => ("sstp_pool", "sstp_service"),
        Server::OpenConnect => ("openconnect_pool", "openconnect_service"),
    };
    let edit = |form: &str| {
        viewer.allows(operation.0).then(|| {
            with_query(
                viewer,
                &format!("vpn/form/{form}"),
                &[("server", server.slug())],
            )
        })
    };
    let panel = Panel::new(locale, &format!("vpn-{}", server.slug()), server.title())
        .state(&state(locale, Some(on)))
        .row(
            (locale, keys::WEB_VPN_SERVER_INTERFACE),
            shown(config.interface.as_ref()),
            None,
        )
        .row(
            (locale, keys::WEB_VPN_POOL),
            shown(config.pool_range.as_ref()),
            edit("pool"),
        )
        .row(
            (locale, keys::WEB_VPN_DNS),
            shown(config.dns_servers.as_ref()),
            edit("dns"),
        );
    if viewer.allows(operation.1) {
        panel.act(toggle(viewer, (server.slug(), on)))
    } else {
        panel
    }
}

/// The servers tab: the PPTP/L2TP, SSTP and OpenConnect servers, IPsec/IKEv2, the
/// WireGuard server interfaces, and how users get access.
pub(crate) fn servers(status: &VpnServerStatus, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let mut region = Region::new(locale);
    for (server, config, name) in [
        (Server::Vpn, &status.vpn, "vpn-server"),
        (Server::Sstp, &status.sstp, "sstp-server"),
        (Server::OpenConnect, &status.openconnect, "oc-server"),
    ] {
        region = region.panel(server_panel(
            server,
            (config, running(status, name)),
            viewer,
        ));
    }
    let on = running(status, "ipsec");
    let virtual_ip = &status.ipsec_virtual_ip;
    let edit = viewer
        .allows("ipsec_virtual_ip")
        .then(|| viewer.href("vpn/form/ipsec"));
    let enabled = virtual_ip.get("enable").map(|value| {
        tr(
            locale,
            if value == &Value::Bool(false) {
                keys::WEB_VPN_OFF
            } else {
                keys::WEB_VPN_ON
            },
            None,
        )
    });
    let mut ipsec = Panel::new(locale, "vpn-ipsec", keys::WEB_VPN_SERVER_IPSEC)
        .state(&state(locale, Some(on)))
        .row((locale, keys::WEB_VPN_VIRTUAL_IP), enabled, edit.clone())
        .row(
            (locale, keys::WEB_VPN_POOL),
            shown(virtual_ip.get("range")),
            edit.clone(),
        )
        .row(
            (locale, keys::WEB_VPN_DNS),
            shown(virtual_ip.get("dns-servers")),
            edit,
        );
    if viewer.allows("ipsec_service") {
        ipsec = ipsec.act(toggle(viewer, ("ipsec", on)));
    }
    let bound: Vec<String> = status
        .wireguard_interfaces
        .iter()
        .filter_map(|item| shown(Some(item.get("interface").unwrap_or(item))))
        .collect();
    let note = if bound.is_empty() {
        keys::WEB_VPN_WIREGUARD_NONE
    } else {
        keys::WEB_VPN_WIREGUARD_NOTE
    };
    let wireguard = Panel::new(locale, "vpn-wireguard", keys::WEB_VPN_SERVER_WIREGUARD)
        .note(tr(locale, note, None))
        .items(bound);
    let access = Panel::new(locale, "vpn-access", keys::WEB_VPN_ACCESS)
        .note(tr(locale, keys::WEB_VPN_ACCESS_NOTE, None))
        .act(Act::link(
            locale,
            keys::WEB_VPN_ACCESS_USERS,
            viewer.href("system/users"),
        ));
    (
        region.panel(ipsec).panel(wireguard).panel(access),
        Vec::new(),
    )
}
