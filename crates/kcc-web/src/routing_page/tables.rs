//! The views of the routing tables: the static routes with Remove, the routing table, and
//! the connection policies with their interfaces in order and their action menus.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    policy_rows::{Permit, Policy},
    route_rows::{Family, StaticRoute},
    table_rows::TableRoute,
};
use crate::{
    page_kit::{gate::Controls, request::with_query},
    table::{
        acts::{Act, MenuItem},
        cells::{Cell, Layout, Ordered},
        head::Head,
        piece::Piece,
        rows::Table,
        view::TableView,
    },
};

/// The table class of every routing table.
const CLASS: &str = "table routing-table";

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// The static routes of `family` on `router`, with Remove when `removable`.
pub(crate) fn static_view(
    (router, family): (&str, Family),
    table: &Table<StaticRoute>,
    (removable, locale): (bool, Locale),
) -> TableView {
    let metrics = family == Family::V4;
    let mut view = TableView::filtered(CLASS, table, (locale, keys::WEB_ROUTING_STATIC_EMPTY));
    for (column, key) in [
        ("destination", keys::WEB_ROUTING_COL_DESTINATION),
        ("gateway", keys::WEB_ROUTING_COL_GATEWAY),
        ("interface", keys::WEB_ROUTING_COL_INTERFACE),
        ("metric", keys::WEB_ROUTING_COL_METRIC),
    ] {
        if metrics || column != "metric" {
            view = view.head(Head::sorted(said(locale, key), table.header(column)));
        }
    }
    if removable {
        view = view.head(Head::hidden(said(locale, keys::WEB_CLIENTS_ACTIONS)));
    }
    for (index, route) in table.rows().iter().enumerate() {
        let id = format!("route-{}", index.saturating_add(1));
        let mut cells = vec![
            Cell::code(route.destination())
                .attr("id", id.clone())
                .head(),
            Cell::optional(route.gateway().map(str::to_owned)).class("mono"),
            Cell::optional(route.interface().map(str::to_owned)).class("mono"),
        ];
        if metrics {
            cells.push(Cell::optional(
                route.metric().map(|metric| metric.to_string()),
            ));
        }
        if removable {
            let pairs = route.pairs();
            let borrowed: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            let href = with_query(&format!("/ui/r/{router}/routing/route/remove"), &borrowed);
            let remove = Act::opens(said(locale, keys::WEB_ROUTING_REMOVE), href).danger();
            cells.push(Cell::acts(Layout::Inline, vec![remove], id).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}

/// The routing table: static routes marked as such, every other route with where the
/// router got it.
pub(crate) fn route_table_view(table: &Table<TableRoute>, locale: Locale) -> TableView {
    let mut view = TableView::filtered(CLASS, table, (locale, keys::WEB_ROUTING_TABLE_EMPTY));
    for (column, key) in [
        ("destination", keys::WEB_ROUTING_COL_DESTINATION),
        ("gateway", keys::WEB_ROUTING_COL_GATEWAY),
        ("interface", keys::WEB_ROUTING_COL_INTERFACE),
        ("metric", keys::WEB_ROUTING_COL_METRIC),
        ("source", keys::WEB_ROUTING_COL_SOURCE),
    ] {
        view = view.head(Head::sorted(said(locale, key), table.header(column)));
    }
    for route in table.rows() {
        let source = if route.is_static() {
            vec![Piece::text(said(locale, keys::WEB_ROUTING_SOURCE_STATIC))]
        } else {
            route
                .source()
                .map(|source| Piece::span("mono", source.to_owned()))
                .into_iter()
                .collect()
        };
        view = view.row(vec![
            Cell::code(route.destination().to_owned()).head(),
            Cell::optional(route.gateway().map(str::to_owned)).class("mono"),
            Cell::optional(route.interface().map(str::to_owned)).class("mono"),
            Cell::optional(route.metric().map(str::to_owned)),
            Cell::of(source),
        ]);
    }
    view
}

/// The address of the policy action `action` on `policy` on `router`, with `extra`
/// parameters.
fn policy_url((router, action): (&str, &str), policy: &Policy, extra: &[(&str, &str)]) -> String {
    let mut pairs = vec![("name", policy.name())];
    pairs.extend_from_slice(extra);
    with_query(&format!("/ui/r/{router}/routing/policy/{action}"), &pairs)
}

/// The label of `permit` in `locale`: the interface, with its order when set.
fn permit_label(locale: Locale, permit: &Permit) -> String {
    permit.order().map_or_else(
        || permit.interface().to_owned(),
        |order| {
            let mut args = FluentArgs::new();
            args.set("name", permit.interface().to_owned());
            args.set("value", order.to_string());
            tr(locale, keys::WEB_ROUTING_POLICY_ORDER, Some(&args))
        },
    )
}

/// The interfaces cell of `policy`, row `item`: the interfaces in order, each with Remove
/// when `controls` allow it.
fn permits_cell(
    router: &str,
    (policy, item): (&Policy, usize),
    (controls, locale): (&Controls, Locale),
) -> Cell {
    if policy.permits().is_empty() {
        let none = Act::note(said(locale, keys::WEB_ROUTING_POLICY_NO_INTERFACES));
        return Cell::acts(Layout::Block, vec![none], String::new());
    }
    let items = policy
        .permits()
        .iter()
        .enumerate()
        .map(|(index, permit)| {
            let id = format!("policy-{item}-permit-{}", index.saturating_add(1));
            let mut acts = Vec::new();
            if controls.allows("permit") {
                let extra = [("interface", permit.interface())];
                let href = policy_url((router, "unpermit"), policy, &extra);
                acts.push(Act::sends(said(locale, keys::WEB_ROUTING_REMOVE), href));
            }
            let piece = Piece::text(permit_label(locale, permit)).attr("id", id.clone());
            (piece, acts, format!("policy-{item} {id}"))
        })
        .collect();
    Cell::ordered(Ordered::new(
        ("routing-permits", "routing-permits__item"),
        items,
    ))
}

/// The action menu of `policy`, row `item`, with the entries `controls` allow.
fn policy_menu(
    router: &str,
    (policy, item): (&Policy, usize),
    (controls, locale): (&Controls, Locale),
) -> Act {
    let mut entries = Vec::new();
    if controls.allows("description") {
        let href = policy_url((router, "description"), policy, &[]);
        entries.push(MenuItem::open(
            said(locale, keys::WEB_ROUTING_POLICY_DESCRIPTION),
            href,
        ));
    }
    if controls.allows("permit") {
        let href = policy_url((router, "permit"), policy, &[]);
        entries.push(MenuItem::open(
            said(locale, keys::WEB_ROUTING_POLICY_PERMIT),
            href,
        ));
    }
    if controls.allows("multipath") {
        let (value, label) = if policy.multipath() {
            ("off", keys::WEB_ROUTING_MULTIPATH_OFF)
        } else {
            ("on", keys::WEB_ROUTING_MULTIPATH_ON)
        };
        let href = policy_url((router, "multipath"), policy, &[("value", value)]);
        entries.push(MenuItem::post(said(locale, label), href));
    }
    if controls.allows("policy") {
        let href = policy_url((router, "delete"), policy, &[]);
        entries.push(MenuItem::open(said(locale, keys::COMMON_DELETE), href).danger());
    }
    let label = said(locale, keys::WEB_CLIENTS_ACTIONS);
    Act::menu(label, format!("policy-menu-{item}"), entries)
}

/// The connection policies on `router` with the row actions `controls` allow.
pub(crate) fn policies_view(
    router: &str,
    table: &Table<Policy>,
    (controls, locale): (&Controls, Locale),
) -> TableView {
    let editable = ["policy", "description", "permit", "multipath"]
        .into_iter()
        .any(|name| controls.allows(name));
    let mut view = TableView::filtered(CLASS, table, (locale, keys::WEB_ROUTING_POLICIES_EMPTY))
        .head(Head::sorted(
            said(locale, keys::WEB_ROUTING_COL_NAME),
            table.header("name"),
        ))
        .head(Head::sorted(
            said(locale, keys::WEB_ROUTING_COL_DESCRIPTION),
            table.header("description"),
        ))
        .head(Head::plain(said(locale, keys::WEB_ROUTING_COL_INTERFACES)))
        .head(Head::sorted(
            said(locale, keys::WEB_ROUTING_COL_MULTIPATH),
            table.header("multipath"),
        ));
    if editable {
        view = view.head(Head::hidden(said(locale, keys::WEB_CLIENTS_ACTIONS)));
    }
    for (index, policy) in table.rows().iter().enumerate() {
        let item = index.saturating_add(1);
        let multipath = if policy.multipath() {
            Piece::text(said(locale, keys::COMMON_ENABLED))
        } else {
            Piece::span("muted", said(locale, keys::COMMON_DISABLED))
        };
        let mut cells = vec![
            Cell::code(policy.name().to_owned())
                .attr("id", format!("policy-{item}"))
                .head(),
            Cell::optional(policy.description().map(str::to_owned)),
            permits_cell(router, (policy, item), (controls, locale)),
            Cell::of(vec![multipath]),
        ];
        if editable {
            let menu = policy_menu(router, (policy, item), (controls, locale));
            cells.push(
                Cell::acts(Layout::Block, vec![menu], format!("policy-{item}"))
                    .class("lan-actions"),
            );
        }
        view = view.row(cells);
    }
    view
}
