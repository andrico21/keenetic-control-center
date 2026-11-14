//! The firewall page's table regions: the lists applied to interfaces, and the UPnP
//! redirects.

use askama::Template;
use kcc_domain::firewall::model::UpnpRedirect;
use kcc_i18n::{bundle::tr, keys};

use super::{lists_region::direction_label, snapshot::Binding};
use crate::{
    page::{Localize as _, Shell},
    page_kit::request::with_query,
    routing_page::frame::protocol_text,
    table::{
        Direction, Sort,
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        rows::{Row, SortKey, Table},
        view::TableView,
    },
};

impl Row for Binding {
    const COLUMNS: &'static [&'static str] = &["interface", "direction", "list"];

    const DEFAULT: Sort = Sort::new("interface", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "direction" => SortKey::text(self.direction()),
            "list" => SortKey::text(self.list()),
            _ => SortKey::text(self.interface()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [self.interface(), self.list(), self.direction()]
            .into_iter()
            .any(|text| text.to_lowercase().contains(needle))
    }
}

/// The lists applied to interfaces (`partials/firewall_bindings.html`).
#[derive(Template)]
#[template(path = "partials/firewall_bindings.html")]
pub(crate) struct BindingsRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// The shown page of bindings.
    table: TableView,
}

localized!(BindingsRegion);

impl BindingsRegion {
    /// The region of `table` on `router` in `shell`, with Remove when `removable`.
    pub(crate) fn new(
        shell: Shell,
        router: &str,
        (table, removable): (&Table<Binding>, bool),
    ) -> Self {
        let locale = shell.locale();
        let mut view = TableView::filtered(
            "table routing-table",
            table,
            (locale, keys::WEB_FIREWALL_BINDINGS_EMPTY),
        );
        for (column, key) in [
            ("interface", keys::WEB_ROUTING_COL_INTERFACE),
            ("direction", keys::WEB_FIREWALL_COL_DIRECTION),
            ("list", keys::WEB_FIREWALL_COL_LIST),
        ] {
            view = view.head(Head::sorted(tr(locale, key, None), table.header(column)));
        }
        if removable {
            view = view.head(Head::hidden(tr(locale, keys::WEB_CLIENTS_ACTIONS, None)));
        }
        for (index, binding) in table.rows().iter().enumerate() {
            let id = format!("binding-{}", index.saturating_add(1));
            let direction = direction_label(binding.direction());
            let mut cells = vec![
                Cell::code(binding.interface().to_owned())
                    .attr("id", id.clone())
                    .head(),
                Cell::text(tr(locale, direction, None)),
                Cell::code(binding.list().to_owned()),
            ];
            if removable {
                let href = with_query(
                    &format!("/ui/r/{router}/firewall/unbind"),
                    &[
                        ("interface", binding.interface()),
                        ("list", binding.list()),
                        ("direction", binding.direction()),
                    ],
                );
                let remove = Act::opens(tr(locale, keys::WEB_ROUTING_REMOVE, None), href).danger();
                cells.push(Cell::acts(Layout::Inline, vec![remove], id).class("lan-actions"));
            }
            view = view.row(cells);
        }
        Self {
            shell,
            oob: false,
            table: view,
        }
    }

    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}

/// One UPnP redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Redirect {
    /// Protocol.
    protocol: Option<String>,
    /// Public port.
    external_port: Option<u16>,
    /// Internal address.
    internal_address: Option<String>,
    /// Internal port.
    internal_port: Option<u16>,
    /// The device's description.
    description: Option<String>,
}

impl Redirect {
    /// The redirect of one `show upnp redirect` row.
    pub(crate) fn new(row: &UpnpRedirect) -> Self {
        Self {
            protocol: row.protocol.clone(),
            external_port: row.external_port,
            internal_address: row.internal_address.clone(),
            internal_port: row.internal_port,
            description: row.description.clone(),
        }
    }

    /// Protocol.
    pub(crate) fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Public port.
    pub(crate) const fn external_port(&self) -> Option<u16> {
        self.external_port
    }

    /// Internal address.
    pub(crate) fn internal_address(&self) -> Option<&str> {
        self.internal_address.as_deref()
    }

    /// Internal port.
    pub(crate) const fn internal_port(&self) -> Option<u16> {
        self.internal_port
    }

    /// The device's description.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl Row for Redirect {
    const COLUMNS: &'static [&'static str] = &[
        "external",
        "protocol",
        "internal",
        "internal_port",
        "description",
    ];

    const DEFAULT: Sort = Sort::new("external", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        let port = |value: Option<u16>| {
            value.map_or(SortKey::Missing, |found| SortKey::Number(i128::from(found)))
        };
        let text = |value: Option<&str>| value.map_or(SortKey::Missing, SortKey::text);
        match column {
            "protocol" => text(self.protocol()),
            "internal" => text(self.internal_address()),
            "internal_port" => port(self.internal_port),
            "description" => text(self.description()),
            _ => port(self.external_port),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        let ports = [self.external_port, self.internal_port]
            .into_iter()
            .flatten()
            .map(|port| port.to_string());
        [self.protocol(), self.internal_address(), self.description()]
            .into_iter()
            .flatten()
            .map(str::to_lowercase)
            .chain(ports)
            .any(|text| text.contains(needle))
    }
}

/// The UPnP redirects, read only (`partials/firewall_upnp.html`).
#[derive(Template)]
#[template(path = "partials/firewall_upnp.html")]
pub(crate) struct UpnpRegion {
    /// Locale carrier.
    shell: Shell,
    /// The shown page of redirects.
    table: TableView,
}

localized!(UpnpRegion);

impl UpnpRegion {
    /// The region of `table` in `shell`.
    pub(crate) fn new(shell: Shell, table: &Table<Redirect>) -> Self {
        let locale = shell.locale();
        let empty = (locale, keys::WEB_FIREWALL_UPNP_EMPTY);
        let mut view = TableView::filtered("table routing-table", table, empty);
        for (column, key) in [
            ("external", keys::WEB_FIREWALL_COL_EXTERNAL_PORT),
            ("protocol", keys::WEB_ROUTING_COL_PROTOCOL),
            ("internal", keys::WEB_FIREWALL_COL_INTERNAL),
            ("internal_port", keys::WEB_FIREWALL_COL_INTERNAL_PORT),
            ("description", keys::WEB_ROUTING_COL_DESCRIPTION),
        ] {
            view = view.head(Head::sorted(tr(locale, key, None), table.header(column)));
        }
        let port = |value: Option<u16>| Cell::optional(value.map(|found| found.to_string()));
        for row in table.rows() {
            let protocol = row.protocol().map(|name| protocol_text(locale, name));
            view = view.row(vec![
                port(row.external_port()).class("numeric").head(),
                Cell::text(protocol.unwrap_or_default()),
                Cell::optional(row.internal_address().map(str::to_owned)).class("mono"),
                port(row.internal_port()).class("numeric"),
                Cell::optional(row.description().map(str::to_owned)),
            ]);
        }
        Self { shell, table: view }
    }
}
