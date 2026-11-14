//! The rules table of one access list: the rules in the order the router checks them (not
//! sortable: the order is the rule), each with its move buttons and action menu.

use core::iter;

use fluent_bundle::FluentArgs;
use kcc_domain::firewall::{
    lists::{AccessList, ListEntry},
    rule_words::Side,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::rule::{action_label, address_text, protocol_label};
use crate::{
    page_kit::request::with_query,
    table::{
        acts::{Act, MenuItem},
        cells::{Cell, Layout},
        head::Head,
        piece::Piece,
        view::TableView,
    },
};

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// One side as people read it in `locale`: the address (or Any) and the port.
fn side(locale: Locale, side: &Side) -> String {
    let address =
        address_text(side).unwrap_or_else(|| said(locale, keys::WEB_FIREWALL_ANY_ADDRESS));
    match side.port() {
        None => address,
        Some(port) => {
            let mut args = FluentArgs::new();
            args.set("port", port.to_string());
            format!(
                "{address} {}",
                tr(locale, keys::WEB_FIREWALL_PORT, Some(&args))
            )
        }
    }
}

/// The address of the rule action `action` on `entry` of `list` on `router`.
fn rule_url((router, action): (&str, &str), list: &AccessList, entry: &ListEntry) -> String {
    let index = entry.index().to_string();
    let words = entry.rule().text();
    with_query(
        &format!("/ui/r/{router}/firewall/rule/{action}"),
        &[("list", list.name()), ("index", &index), ("rule", &words)],
    )
}

/// The cells of `entry` showing the rule: decision, protocol, source and destination, or
/// the stored words of a rule in another form across all four.
fn rule_cells(locale: Locale, entry: &ListEntry) -> Vec<Cell> {
    let note = entry
        .disabled()
        .then(|| Piece::span("firewall-rules__note", said(locale, keys::COMMON_DISABLED)));
    let Some(rule) = entry.rule().form() else {
        let pieces = iter::once(Piece::text(entry.rule().text())).chain(note);
        return vec![
            Cell::of(pieces.collect())
                .class("mono")
                .attr("colspan", "4".to_owned()),
        ];
    };
    let action = iter::once(Piece::text(said(locale, action_label(rule.action())))).chain(note);
    let protocol = protocol_label(rule.protocol()).map(|label| said(locale, label));
    vec![
        Cell::of(action.collect()),
        Cell::text(protocol.unwrap_or_default()),
        Cell::code(side(locale, rule.source())),
        Cell::code(side(locale, rule.destination())),
    ]
}

/// The move buttons and the action menu of rule `row` of `list`, list `item`.
fn rule_actions(
    router: &str,
    (list, entry): (&AccessList, &ListEntry),
    (item, row, locale): (usize, usize, Locale),
) -> Vec<Act> {
    let moving = rule_url((router, "move"), list, entry);
    let mut acts = Vec::new();
    if let Some(to) = entry.index().checked_sub(1) {
        let href = format!("{moving}&to={to}");
        acts.push(Act::sends(said(locale, keys::WEB_FIREWALL_MOVE_UP), href));
    }
    let to = entry.index().saturating_add(1);
    if to < list.entries().len() {
        let href = format!("{moving}&to={to}");
        acts.push(Act::sends(said(locale, keys::WEB_FIREWALL_MOVE_DOWN), href));
    }
    let (value, state) = if entry.disabled() {
        ("on", keys::WEB_FIREWALL_ENABLE)
    } else {
        ("off", keys::WEB_FIREWALL_DISABLE)
    };
    let state_url = format!("{}&value={value}", rule_url((router, "state"), list, entry));
    let mut entries = vec![
        MenuItem::post(said(locale, state), state_url),
        MenuItem::open(
            said(locale, keys::WEB_ROUTING_COL_DESCRIPTION),
            rule_url((router, "description"), list, entry),
        ),
        MenuItem::open(
            said(locale, keys::WEB_FIREWALL_SCHEDULE),
            rule_url((router, "schedule"), list, entry),
        ),
    ];
    if entry.rule().form().is_some() {
        let href = rule_url((router, "remove"), list, entry);
        entries.push(MenuItem::open(said(locale, keys::WEB_ROUTING_REMOVE), href).danger());
    }
    let menu = format!("acl-{item}-menu-{row}");
    acts.push(Act::menu(
        said(locale, keys::WEB_CLIENTS_ACTIONS),
        menu,
        entries,
    ));
    acts
}

/// The rules of `list`, list `item` of the page, on `router`, with their actions when
/// the role may change `rules`, in `locale`.
pub(crate) fn rules_view(
    router: &str,
    (list, item): (&AccessList, usize),
    (rules, locale): (bool, Locale),
) -> TableView {
    let empty = TableView::new("table routing-table firewall-rules").nested();
    if list.entries().is_empty() {
        return empty.blank("page__text", said(locale, keys::WEB_FIREWALL_RULES_EMPTY));
    }
    let position = Head::plain(said(locale, keys::WEB_FIREWALL_COL_POSITION));
    let mut view = empty.head(position.with_class("numeric"));
    for key in [
        keys::WEB_FIREWALL_COL_ACTION,
        keys::WEB_ROUTING_COL_PROTOCOL,
        keys::WEB_NAT_COL_SOURCE,
        keys::WEB_NAT_COL_DESTINATION,
        keys::WEB_ROUTING_COL_DESCRIPTION,
    ] {
        view = view.head(Head::plain(said(locale, key)));
    }
    if rules {
        view = view.head(Head::hidden(said(locale, keys::WEB_CLIENTS_ACTIONS)));
    }
    for (index, entry) in list.entries().iter().enumerate() {
        let row = index.saturating_add(1);
        let id = format!("acl-{item}-rule-{row}");
        let mut cells = vec![
            Cell::text(entry.position().to_string())
                .class("numeric")
                .attr("id", id.clone())
                .head(),
        ];
        cells.extend(rule_cells(locale, entry));
        let schedule = entry.schedule().map(|name| {
            let label = said(locale, keys::WEB_FIREWALL_COL_SCHEDULE);
            Piece::span("firewall-rules__note", format!("{label}: "))
                .with_inner("mono", name.to_owned())
        });
        let description = entry.description().map(|text| Piece::text(text.to_owned()));
        cells.push(Cell::of(description.into_iter().chain(schedule).collect()));
        if rules {
            let acts = rule_actions(router, (list, entry), (item, row, locale));
            let wrapped = Layout::Wrapped("firewall-rules__actions");
            cells.push(Cell::acts(wrapped, acts, format!("acl-{item} {id}")).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}
