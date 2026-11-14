//! The rows of the clients table: the name with its state flags, the addresses, signal,
//! traffic, policy, access and schedule, and the action menu the role may use.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use super::client_rows::ClientRow;
use crate::{
    page_kit::gate::Controls,
    table::{
        acts::{Act, MenuItem},
        cells::{Cell, Layout},
        head::Head,
        piece::{Line, Piece},
        rows::Table,
        view::TableView,
    },
};

/// The sortable columns, in order, and their labels.
pub(super) const COLUMNS: [(&str, MessageKey); 9] = [
    ("name", keys::WEB_CLIENTS_COL_NAME),
    ("mac", keys::WEB_CLIENTS_COL_MAC),
    ("ip", keys::WEB_CLIENTS_COL_IP),
    ("interface", keys::WEB_CLIENTS_COL_INTERFACE),
    ("signal", keys::WEB_CLIENTS_COL_SIGNAL),
    ("traffic", keys::WEB_CLIENTS_COL_TRAFFIC),
    ("policy", keys::WEB_CLIENTS_COL_POLICY),
    ("access", keys::WEB_CLIENTS_COL_ACCESS),
    ("schedule", keys::WEB_CLIENTS_COL_SCHEDULE),
];

/// The table class.
pub(super) const CLASS: &str = "table lan-table";

/// Who looks at the table: the router, what the role may change and the locale.
pub(super) type Viewer<'region> = (&'region str, &'region Controls, Locale);

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// The route of `action` on the client of `row` on `router`.
fn action_url(router: &str, action: &str, row: &ClientRow) -> String {
    let mac: String = byte_serialize(row.mac().as_bytes()).collect();
    format!("/ui/r/{router}/clients/{action}?mac={mac}")
}

/// The shown page of `table` under `heads`, with the action menus when `actions`.
pub(super) fn view(
    heads: Vec<Head>,
    table: &Table<ClientRow>,
    (viewer, actions): (Viewer<'_>, bool),
) -> TableView {
    let locale = viewer.2;
    let mut view = heads
        .into_iter()
        .fold(TableView::new(CLASS), TableView::head);
    if actions {
        view = view.head(Head::hidden(said(locale, keys::WEB_CLIENTS_ACTIONS)));
    }
    for (index, row) in table.rows().iter().enumerate() {
        let item = index.saturating_add(1);
        let mut cells = vec![name_cell(row, locale).attr("id", format!("client-{item}"))];
        cells.extend(data_cells(row, locale));
        if actions {
            let menu = Act::menu(
                said(locale, keys::WEB_CLIENTS_ACTIONS),
                format!("client-menu-{item}"),
                menu(row, viewer),
            );
            let described = format!("client-{item}");
            cells.push(Cell::acts(Layout::Block, vec![menu], described).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}

/// The row header of `row`: the name, then its state flags one per line.
fn name_cell(row: &ClientRow, locale: Locale) -> Cell {
    let name = row.name().map_or_else(
        || {
            Piece::span("lan-name", String::new()).with(Piece::span(
                "muted",
                said(locale, keys::WEB_CLIENTS_UNNAMED),
            ))
        },
        |name| Piece::span("lan-name", name.to_owned()),
    );
    let state = if row.online() {
        Piece::span("status", said(locale, keys::WEB_CLIENTS_ONLINE))
            .attr("data-status", "online".to_owned())
    } else {
        Piece::span("status", said(locale, keys::WEB_CLIENTS_OFFLINE))
            .attr("data-status", "unknown".to_owned())
    };
    let mut flags = Piece::span("lan-flags", String::new()).with(state);
    if !row.registered() {
        flags = flags.with(
            Piece::span("flag", said(locale, keys::WEB_CLIENTS_UNREGISTERED))
                .attr("data-tone", "info".to_owned()),
        );
    }
    Cell::stack(vec![Line::Piece(name), Line::Open(flags)]).head()
}

/// The data cells of `row`.
fn data_cells(row: &ClientRow, locale: Locale) -> [Cell; 8] {
    let owned = |value: Option<&str>| value.map(str::to_owned);
    let signal = row.signal().map_or_else(
        || Piece::span("muted", said(locale, keys::WEB_CLIENTS_WIRED)),
        |signal| Piece::text(signal.to_owned()),
    );
    let access = if row.blocked() {
        Piece::span("flag", said(locale, keys::WEB_CLIENTS_BLOCKED))
            .attr("data-tone", "error".to_owned())
    } else {
        Piece::text(said(locale, keys::WEB_CLIENTS_ALLOWED))
    };
    [
        Cell::code(row.mac().to_owned()),
        Cell::optional(owned(row.ip())).class("mono"),
        Cell::optional(owned(row.interface())).class("mono"),
        Cell::of(vec![signal]).class("numeric"),
        Cell::optional(owned(row.traffic())).class("numeric"),
        Cell::optional(owned(row.policy())),
        Cell::of(vec![access]),
        Cell::optional(owned(row.schedule())),
    ]
}

/// The menu entries of `row` the viewer's role may use.
fn menu(row: &ClientRow, (router, controls, locale): Viewer<'_>) -> Vec<MenuItem> {
    let url = |action: &str| action_url(router, action, row);
    let mut items = Vec::new();
    if controls.allows("register") {
        let label = if row.registered() {
            keys::WEB_CLIENTS_ACTION_RENAME
        } else {
            keys::WEB_CLIENTS_ACTION_REGISTER
        };
        items.push(MenuItem::open(said(locale, label), url("name")));
    }
    if controls.allows("access") {
        let (value, label) = if row.blocked() {
            ("permit", keys::WEB_CLIENTS_ACTION_PERMIT)
        } else {
            ("deny", keys::WEB_CLIENTS_ACTION_BLOCK)
        };
        let fields = vec![("value", value.to_owned())];
        items.push(MenuItem::form(said(locale, label), (url("access"), fields)));
    }
    for (name, label) in [
        ("policy", keys::WEB_CLIENTS_ACTION_POLICY),
        ("schedule", keys::WEB_CLIENTS_ACTION_SCHEDULE),
        ("priority", keys::WEB_CLIENTS_ACTION_PRIORITY),
    ] {
        if controls.allows(name) {
            items.push(MenuItem::open(said(locale, label), url(name)));
        }
    }
    if controls.allows("wake") {
        let label = said(locale, keys::WEB_CLIENTS_ACTION_WAKE);
        items.push(MenuItem::form(label, (url("wake"), Vec::new())));
    }
    if controls.allows("remove") && row.registered() {
        let label = said(locale, keys::WEB_CLIENTS_ACTION_REMOVE);
        items.push(MenuItem::open(label, url("remove")).danger());
    }
    items
}
