//! The views of the network tables: the interfaces, the internet connections in priority
//! order, the ping-check profiles and the mesh members, each with the actions the role
//! may run.

use core::iter;

use kcc_domain::mesh::Member;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    net_interface_line::Line,
    net_internet_order::reorder,
    net_wan::Link,
    page_kit::{gate::Controls, request::with_query},
    table::{
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        piece::Piece,
        rows::{Row as _, Table},
        view::TableView,
    },
};

/// The table class of every network table.
const CLASS: &str = "table net-table";

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// A row header of the identifier `id` with its `note`, as element `head_id`.
fn named(id: &str, note: Option<&str>, head_id: String) -> Cell {
    let noted = note.map(|text| Piece::span("net-table__note", text.to_owned()));
    let pieces = iter::once(Piece::span("mono", id.to_owned())).chain(noted);
    Cell::of(pieces.collect()).attr("id", head_id).head()
}

/// The interfaces on `router` with Details and, where `controls` allow it, Enable or
/// Disable.
pub(crate) fn interfaces_view(
    router: &str,
    table: &Table<Line>,
    (controls, locale): (&Controls, Locale),
) -> TableView {
    let mut view = TableView::counted(
        CLASS,
        table,
        (locale, keys::WEB_NETWORK_FILTER, keys::WEB_NETWORK_NONE),
    );
    for (column, key) in [
        ("name", keys::WEB_NETWORK_INTERFACE),
        ("type", keys::WEB_NETWORK_TYPE),
        ("link", keys::WEB_NETWORK_LINK),
        ("state", keys::WEB_NETWORK_STATE),
        ("address", keys::WEB_NETWORK_ADDRESS),
        ("security", keys::WEB_NETWORK_SECURITY),
    ] {
        view = view.head(Head::sorted(said(locale, key), table.header(column)));
    }
    view = view.head(Head::hidden(said(locale, keys::WEB_ADMIN_ACTIONS)));
    for (index, line) in table.rows().iter().enumerate() {
        let id = format!("iface-{}", index.saturating_add(1));
        let link = line.link_text(locale).map_or_else(
            || Cell::missing(locale, keys::WEB_KIT_NOT_REPORTED),
            |label| {
                Cell::of(vec![
                    Piece::span("status", label).attr("data-status", line.link_value().to_owned()),
                ])
            },
        );
        let detail = with_query(
            &format!("/ui/r/{router}/network/detail"),
            &[("name", line.id())],
        );
        let mut acts = vec![Act::opens(said(locale, keys::WEB_NETWORK_DETAILS), detail)];
        let (operation, label) = if line.enabled() == Some(false) {
            ("up", keys::WEB_NETWORK_ENABLE)
        } else {
            ("down", keys::WEB_NETWORK_DISABLE)
        };
        if controls.allows(operation) {
            let href = with_query(
                &format!("/ui/r/{router}/network/state"),
                &[("name", line.id()), ("state", operation)],
            );
            acts.push(Act::sends(said(locale, label), href));
        }
        view = view.row(vec![
            named(line.id(), line.description(), id.clone()),
            Cell::reported(locale, line.kind().map(str::to_owned)),
            link,
            Cell::reported(locale, line.state_text(locale)),
            Cell::optional(line.address().map(str::to_owned)).class("mono"),
            Cell::reported(locale, line.level_text(locale)),
            Cell::acts(Layout::Wrapped("admin-actions"), acts, id),
        ]);
    }
    view
}

/// The actions on connection `link`: Move up and Move down while the table shows the
/// priority order and `controls` allow it, Settings, and Delete where allowed.
fn link_acts(
    router: &str,
    (table, link): (&Table<Link>, &Link),
    (controls, locale): (&Controls, Locale),
) -> Vec<Act> {
    let ordered = table.sort() == Link::DEFAULT && table.filter().is_empty();
    let mut acts = Vec::new();
    for (up, label) in [
        (true, keys::WEB_INTERNET_MOVE_UP),
        (false, keys::WEB_INTERNET_MOVE_DOWN),
    ] {
        if ordered
            && controls.allows("priority")
            && !reorder(table.rows(), link.id(), up).is_empty()
        {
            let href = with_query(
                &format!("/ui/r/{router}/internet/order"),
                &[
                    ("name", link.id()),
                    ("move", if up { "up" } else { "down" }),
                ],
            );
            acts.push(Act::sends(said(locale, label), href));
        }
    }
    let settings = with_query(
        &format!("/ui/r/{router}/internet/settings"),
        &[("name", link.id())],
    );
    acts.push(Act::opens(
        said(locale, keys::WEB_INTERNET_SETTINGS),
        settings,
    ));
    if controls.allows("delete") {
        let href = with_query(
            &format!("/ui/r/{router}/internet/delete"),
            &[("name", link.id())],
        );
        acts.push(Act::opens(said(locale, keys::COMMON_DELETE), href).danger());
    }
    acts
}

/// The internet connections on `router` in priority order, with the actions `controls`
/// allow.
pub(crate) fn connections_view(
    router: &str,
    table: &Table<Link>,
    (controls, locale): (&Controls, Locale),
) -> TableView {
    let mut view = TableView::counted(
        CLASS,
        table,
        (locale, keys::WEB_INTERNET_FILTER, keys::WEB_INTERNET_NONE),
    );
    for (column, key) in [
        ("priority", keys::WEB_NETWORK_PRIORITY),
        ("name", keys::WEB_INTERNET_CONNECTION),
        ("type", keys::WEB_INTERNET_KIND),
        ("state", keys::WEB_NETWORK_STATE),
    ] {
        view = view.head(Head::sorted(said(locale, key), table.header(column)));
    }
    view = view
        .head(Head::plain(said(locale, keys::WEB_NETWORK_ADDRESS)))
        .head(Head::hidden(said(locale, keys::WEB_ADMIN_ACTIONS)));
    for (index, link) in table.rows().iter().enumerate() {
        let id = format!("wan-{}", index.saturating_add(1));
        let acts = link_acts(router, (table, link), (controls, locale));
        view = view.row(vec![
            Cell::reported(locale, link.priority().map(|priority| priority.to_string()))
                .class("numeric"),
            named(link.id(), link.description(), id.clone()),
            Cell::reported(locale, link.kind_text(locale)),
            Cell::reported(locale, link.state_text(locale)),
            Cell::optional(link.address_text(locale)).class("mono"),
            Cell::acts(Layout::Wrapped("admin-actions"), acts, id),
        ]);
    }
    view
}

/// The mesh `members` on `router` with the member actions `controls` allow.
pub(crate) fn mesh_view(
    router: &str,
    members: &[Member],
    (controls, locale): (&Controls, Locale),
) -> TableView {
    let mut view = TableView::new(CLASS);
    if members.is_empty() {
        return view.blank("panel__note", said(locale, keys::WEB_MESH_NONE));
    }
    for key in [
        keys::WEB_MESH_MEMBER,
        keys::WEB_MESH_ID,
        keys::WEB_NETWORK_MAC,
        keys::WEB_MESH_STATUS,
    ] {
        view = view.head(Head::plain(said(locale, key)));
    }
    view = view.head(Head::hidden(said(locale, keys::WEB_ADMIN_ACTIONS)));
    for (index, member) in members.iter().enumerate() {
        let id = format!("member-{}", index.saturating_add(1));
        let (value, key) = match member.online {
            Some(true) => ("online", keys::WEB_ROUTER_ONLINE),
            Some(false) => ("offline", keys::WEB_ROUTER_OFFLINE),
            None => ("unknown", keys::WEB_ROUTER_UNKNOWN),
        };
        let status = Piece::span("status", said(locale, key)).attr("data-status", value.to_owned());
        let acts = member.id.as_deref().map_or_else(Vec::new, |name| {
            [
                ("update_check", "check", keys::WEB_MESH_CHECK, false),
                ("update_start", "update", keys::WEB_MESH_UPDATE, false),
                ("member_reboot", "restart", keys::WEB_MESH_RESTART, true),
            ]
            .into_iter()
            .filter(|(operation, _, _, _)| controls.allows(operation))
            .map(|(_, action, label, destructive)| {
                let href = with_query(
                    &format!("/ui/r/{router}/mesh/action"),
                    &[("name", name), ("do", action)],
                );
                let act = Act::sends(said(locale, label), href);
                if destructive { act.danger() } else { act }
            })
            .collect()
        });
        view = view.row(vec![
            Cell::reported(locale, member.name.clone())
                .attr("id", id.clone())
                .head(),
            Cell::optional(member.id.clone()).class("mono"),
            Cell::optional(member.mac.clone()).class("mono"),
            Cell::of(vec![status]),
            Cell::acts(Layout::Wrapped("admin-actions"), acts, id),
        ]);
    }
    view
}
