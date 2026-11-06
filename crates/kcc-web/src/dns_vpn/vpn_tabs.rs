//! The VPN connection tabs: the connections table and a WireGuard connection's peers,
//! each with the actions the role may use.

use kcc_domain::vpn_clients::{VpnClientStatus, VpnClientType};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use url::form_urlencoded;

use super::{
    cells::{Act, Cell, Pill},
    check,
    flow::Viewer,
    listing::{Line, Listing},
    region::{Panel, Region, TableView},
    vpn_read::{allowed, details, endpoint, is_up, type_label},
};
use crate::table::{Direction, Sort, rows::Table};

/// The connections table.
#[derive(Debug, Clone, Copy)]
struct Connections;

/// The peers table of one WireGuard connection.
#[derive(Debug, Clone, Copy)]
struct Peers;

impl Listing for Connections {
    const COLUMNS: &'static [&'static str] = &["name", "type", "state", "details"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_VPN_NAME,
        keys::WEB_VPN_TYPE,
        keys::WEB_VPN_STATE,
        keys::WEB_VPN_DETAILS,
    ];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_VPN_TAB_CONNECTIONS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_VPN_CONNECTIONS_EMPTY
    }
}

impl Listing for Peers {
    const COLUMNS: &'static [&'static str] =
        &["key", "endpoint", "allowed", "keepalive", "preshared"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_VPN_PUBLIC_KEY,
        keys::WEB_VPN_ENDPOINT,
        keys::WEB_VPN_ALLOWED,
        keys::WEB_VPN_KEEPALIVE,
        keys::WEB_VPN_PRESHARED,
    ];
    const DEFAULT: Sort = Sort::new("key", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_VPN_PEERS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_VPN_PEERS_EMPTY
    }
}

/// `path` of the router with the query `pairs`.
pub(crate) fn with_query(viewer: &Viewer, path: &str, pairs: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
    }
    viewer.href(&format!("{path}?{}", query.finish()))
}

/// The state pill of a connection or a server.
pub(crate) fn state(locale: Locale, up: Option<bool>) -> Cell {
    match up {
        Some(true) => Cell::pill(locale, Pill::On, keys::COMMON_ENABLED),
        Some(false) => Cell::pill(locale, Pill::Off, keys::COMMON_DISABLED),
        None => Cell::missing(locale, keys::COMMON_UNKNOWN),
    }
}

/// Set or not set, for a secret whose value is never shown.
fn presence(locale: Locale, present: bool) -> Cell {
    let key = if present {
        keys::WEB_VPN_SECRET_SET
    } else {
        keys::WEB_VPN_SECRET_UNSET
    };
    Cell::word(locale, key)
}

/// The connections tab: every client connection with its type, state and details.
pub(crate) fn connections(clients: &[VpnClientStatus], viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let lines = clients
        .iter()
        .map(|client| {
            let up = is_up(client);
            let mut line = Line::new(vec![
                Cell::code(client.id.clone()),
                Cell::word(locale, type_label(client.client_type)),
                state(locale, up),
                Cell::codes(locale, details(client, locale), keys::WEB_DNS_NONE).plain(),
            ]);
            let named = [("tunnel", client.id.as_str())];
            if viewer.allows("enabled") {
                let (label, next) = if up == Some(true) {
                    (keys::WEB_VPN_DISABLE, "off")
                } else {
                    (keys::WEB_VPN_ENABLE, "on")
                };
                let fields = vec![("tunnel", client.id.clone()), ("enabled", next.to_owned())];
                line = line.with(Act::post(locale, label, (viewer.href("vpn/state"), fields)));
            }
            if client.client_type == VpnClientType::WireGuard
                && let Some(name) = check::tunnel(&client.id)
            {
                let href = viewer.href(&format!("vpn/peers/{name}"));
                line = line.with(Act::link(locale, keys::WEB_VPN_PEERS, href));
            }
            if viewer.allows("delete") {
                let href = with_query(viewer, "vpn/delete", &named);
                line = line.with(Act::open(locale, keys::COMMON_DELETE, href).danger());
            }
            line
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("vpn"));
    let actions = if viewer.allows("create") {
        vec![
            Act::open(locale, keys::WEB_VPN_IMPORT, viewer.href("vpn/form/import")).primary(),
            Act::open(locale, keys::WEB_VPN_CREATE, viewer.href("vpn/form/create")).secondary(),
        ]
    } else {
        Vec::new()
    };
    let region = Region::new(locale).table(TableView::of(&Connections, &table, locale));
    (region, actions)
}

/// The peers of the WireGuard connection `client`: the router's side, then each peer.
pub(crate) fn peers(client: &VpnClientStatus, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let wireguard = client.wireguard.clone().unwrap_or_default();
    let edits = viewer.allows("wireguard_peer");
    let lines = wireguard
        .peers
        .iter()
        .map(|(key, peer)| {
            let seconds = peer
                .keepalive_interval
                .as_deref()
                .unwrap_or_default()
                .first();
            let keepalive = seconds.map_or_else(
                || Cell::missing(locale, keys::WEB_DNS_NONE),
                |count| Cell::text(count.clone()),
            );
            let line = Line::new(vec![
                Cell::code(key.clone()),
                endpoint(peer)
                    .map_or_else(|| Cell::missing(locale, keys::WEB_DNS_NONE), Cell::code),
                Cell::codes(locale, allowed(peer), keys::WEB_DNS_NONE),
                keepalive,
                presence(
                    locale,
                    peer.preshared_key_present
                        .is_some_and(|marker| marker.present),
                ),
            ]);
            if edits {
                let shown_endpoint = endpoint(peer).unwrap_or_default();
                let pairs = [
                    ("tunnel", client.id.as_str()),
                    ("key", key.as_str()),
                    ("endpoint", shown_endpoint.as_str()),
                    ("keepalive", seconds.map_or("", String::as_str)),
                ];
                line.with(Act::open(
                    locale,
                    keys::COMMON_EDIT,
                    with_query(viewer, "vpn/form/peer", &pairs),
                ))
            } else {
                line
            }
        })
        .collect();
    let table = Table::new(
        lines,
        viewer.query(),
        viewer.href(&format!("vpn/peers/{}", client.id)),
    );
    let private = wireguard
        .private_key_present
        .is_some_and(|marker| marker.present);
    let side = Panel::new(locale, "vpn-side", keys::WEB_VPN_ROUTER_SIDE)
        .note(tr(locale, keys::WEB_VPN_PEERS_NOTE, None))
        .row(
            (locale, keys::WEB_VPN_ROUTER_KEY),
            wireguard.public_key,
            None,
        )
        .row((locale, keys::WEB_VPN_PORT), wireguard.listen_port, None)
        .row(
            (locale, keys::WEB_VPN_PRIVATE_KEY),
            Some(tr(
                locale,
                if private {
                    keys::WEB_VPN_SECRET_SET
                } else {
                    keys::WEB_VPN_SECRET_UNSET
                },
                None,
            )),
            None,
        );
    let actions = edits
        .then(|| {
            let href = with_query(viewer, "vpn/form/peer", &[("tunnel", &client.id)]);
            Act::open(locale, keys::WEB_VPN_PEER_ADD, href).primary()
        })
        .into_iter()
        .collect();
    let region = Region::new(locale)
        .panel(side)
        .table(TableView::of(&Peers, &table, locale));
    (region, actions)
}
