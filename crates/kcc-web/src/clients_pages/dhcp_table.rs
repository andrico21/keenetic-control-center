//! The tables of the DHCP views: pools with Edit, and hosts (static leases, active leases
//! with Reserve, ARP neighbours).

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::dhcp_rows::{HostRow, PoolRow};
use crate::table::{
    acts::Act,
    cells::{Cell, Layout},
    head::Head,
    piece::Piece,
    rows::{Row, Table},
    view::TableView,
};

/// The table class of every DHCP view.
const CLASS: &str = "table lan-table";

/// The link of a row's action, when the role may use it.
pub(super) type RowLink<'region, R> = Option<&'region dyn Fn(&R) -> String>;

/// What a hosts table shows: the interface and state, and the time left on the lease.
pub(super) type HostColumns = (bool, bool);

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// The filtered view of `table` with the sorted `columns`, and a hidden head over the
/// actions when `actions`.
fn headed<R>(
    table: &Table<R>,
    columns: &[(&'static str, MessageKey)],
    (actions, locale): (bool, Locale),
) -> TableView
where
    R: Row,
{
    let mut view = TableView::filtered(CLASS, table, (locale, keys::WEB_KIT_TABLE_EMPTY));
    for (column, key) in columns {
        view = view.head(Head::sorted(said(locale, *key), table.header(column)));
    }
    if actions {
        view = view.head(Head::hidden(said(locale, keys::WEB_CLIENTS_ACTIONS)));
    }
    view
}

/// The pools of `table`, with Edit opening `edit` of each row when the role may.
pub(super) fn pools(
    table: &Table<PoolRow>,
    edit: RowLink<'_, PoolRow>,
    locale: Locale,
) -> TableView {
    let columns = [
        ("name", keys::WEB_DHCP_COL_NAME),
        ("range", keys::WEB_DHCP_COL_RANGE),
        ("gateway", keys::WEB_DHCP_COL_GATEWAY),
        ("dns", keys::WEB_DHCP_COL_DNS),
        ("lease", keys::WEB_DHCP_COL_LEASE),
        ("interface", keys::WEB_DHCP_COL_INTERFACE),
        ("state", keys::WEB_DHCP_COL_STATE),
    ];
    let mut view = headed(table, &columns, (edit.is_some(), locale));
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("pool-{}", index.saturating_add(1));
        let owned = |value: Option<&str>| value.map(str::to_owned);
        let state = if row.enabled() {
            Cell::word(locale, keys::COMMON_ENABLED)
        } else {
            Cell::of(vec![Piece::span(
                "muted",
                said(locale, keys::COMMON_DISABLED),
            )])
        };
        let mut cells = vec![
            Cell::code(row.name().to_owned())
                .attr("id", id.clone())
                .head(),
            Cell::optional(owned(row.range())),
            Cell::optional(owned(row.gateway())).class("mono"),
            Cell::optional(owned(row.dns())).class("mono"),
            Cell::optional(owned(row.lease())).class("numeric"),
            Cell::optional(owned(row.interface())).class("mono"),
            state,
        ];
        if let Some(href) = edit {
            let act = Act::open(locale, keys::COMMON_EDIT, href(row));
            cells.push(Cell::acts(Layout::Inline, vec![act], id).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}

/// The hosts of `table` with the `shown` columns, with Reserve opening `reserve` of each
/// row when the role may.
pub(super) fn hosts(
    table: &Table<HostRow>,
    (shown, reserve): (HostColumns, RowLink<'_, HostRow>),
    locale: Locale,
) -> TableView {
    let (detailed, expiring) = shown;
    let mut columns = vec![
        ("device", keys::WEB_DHCP_COL_DEVICE),
        ("mac", keys::WEB_DHCP_COL_MAC),
        ("address", keys::WEB_DHCP_COL_ADDRESS),
    ];
    if detailed {
        columns.push(("interface", keys::WEB_DHCP_COL_INTERFACE));
        columns.push(("state", keys::WEB_DHCP_COL_STATE));
    }
    if expiring {
        columns.push(("expires", keys::WEB_DHCP_COL_EXPIRES));
    }
    let mut view = headed(table, &columns, (reserve.is_some(), locale));
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("host-{}", index.saturating_add(1));
        let owned = |value: Option<&str>| value.map(str::to_owned);
        let device = row.device().map_or_else(
            || Piece::span("muted", said(locale, keys::WEB_CLIENTS_UNNAMED)),
            |device| Piece::text(device.to_owned()),
        );
        let mut cells = vec![
            Cell::of(vec![device]).attr("id", id.clone()).head(),
            Cell::code(row.mac().to_owned()),
            Cell::optional(owned(row.address())).class("mono"),
        ];
        if detailed {
            cells.push(Cell::optional(owned(row.interface())).class("mono"));
            cells.push(Cell::optional(owned(row.state())));
        }
        if expiring {
            cells.push(Cell::optional(owned(row.expires())).class("numeric"));
        }
        if let Some(href) = reserve {
            let act = Act::open(locale, keys::WEB_DHCP_RESERVE, href(row));
            cells.push(Cell::acts(Layout::Inline, vec![act], id).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}
