//! The DNS tabs: the panels and the table each shows, and the page actions the role may
//! use there.

use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use url::form_urlencoded;

use super::{
    dns_filtering,
    dns_read::{DnsState, Entry, Protocol},
    flow::Viewer,
    listing::{Line, Listing, table_view},
    region::Region,
    screen::Tab,
};
use crate::table::{Direction, Sort, acts::Act, cells::Cell, rows::Table};

/// The servers table.
#[derive(Debug, Clone, Copy)]
struct Servers;

/// The static records table.
#[derive(Debug, Clone, Copy)]
struct Records;

/// The domain lists table.
#[derive(Debug, Clone, Copy)]
struct Lists;

/// The routes table.
#[derive(Debug, Clone, Copy)]
struct Routes;

impl Listing for Servers {
    const COLUMNS: &'static [&'static str] = &["server", "protocol", "options"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_DNS_SERVER,
        keys::WEB_DNS_PROTOCOL,
        keys::WEB_DNS_OPTIONS,
    ];
    const DEFAULT: Sort = Sort::new("protocol", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_DNS_TAB_SERVERS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_DNS_SERVERS_EMPTY
    }
}

impl Listing for Records {
    const COLUMNS: &'static [&'static str] = &["domain", "address"];
    const LABELS: &'static [MessageKey] = &[keys::WEB_DNS_DOMAIN, keys::WEB_DNS_ADDRESS];
    const DEFAULT: Sort = Sort::new("domain", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_DNS_TAB_RECORDS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_DNS_RECORDS_EMPTY
    }
}

impl Listing for Lists {
    const COLUMNS: &'static [&'static str] = &["name", "description", "include", "exclude"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_DNS_LIST,
        keys::WEB_DNS_DESCRIPTION,
        keys::WEB_DNS_INCLUDED,
        keys::WEB_DNS_EXCLUDED,
    ];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_DNS_TAB_LISTS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_DNS_LISTS_EMPTY
    }
}

impl Listing for Routes {
    const COLUMNS: &'static [&'static str] = &["list", "interface", "gateway"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_DNS_LIST,
        keys::WEB_DNS_INTERFACE,
        keys::WEB_DNS_GATEWAY,
    ];
    const DEFAULT: Sort = Sort::new("list", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_DNS_TAB_ROUTES
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_DNS_ROUTES_EMPTY
    }
}

/// The region of the DNS `tab` and the page actions `viewer` may use.
pub(crate) fn tab(state: &DnsState, tab: Tab, viewer: &Viewer) -> (Region, Vec<Act>) {
    match tab {
        Tab::Servers => servers(state, viewer),
        Tab::Filtering => dns_filtering::filtering(state, viewer),
        Tab::Records => records(state, viewer),
        Tab::Lists => lists(state, viewer),
        Tab::Routes => routes(state, viewer),
        Tab::Connections | Tab::VpnServers => (Region::new(viewer.locale()), Vec::new()),
    }
}

/// The dialog `form` of the router as a primary page action.
pub(crate) fn dialog(viewer: &Viewer, label: MessageKey, form: &str) -> Act {
    Act::open(
        viewer.locale(),
        label,
        viewer.href(&format!("dns/form/{form}")),
    )
    .primary()
}

/// The text of value `index` of `entry`, or "none".
pub(crate) fn value(locale: Locale, entry: &Entry, index: usize) -> Cell {
    entry.value(index).map_or_else(
        || Cell::missing(locale, keys::WEB_DNS_NONE),
        |text| Cell::code(text.to_owned()),
    )
}

/// The servers tab.
fn servers(state: &DnsState, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let lines = state
        .servers()
        .into_iter()
        .map(|(protocol, entry)| {
            let label = match protocol {
                Protocol::Tls => keys::WEB_DNS_PROTOCOL_TLS,
                Protocol::Https => keys::WEB_DNS_PROTOCOL_HTTPS,
                Protocol::Plain => keys::WEB_DNS_PROTOCOL_PLAIN,
            };
            Line::new(vec![
                Cell::code(entry.name().to_owned()),
                Cell::word(locale, label),
                value(locale, &entry, 0),
            ])
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("dns"));
    let adds = ["name_server", "tls_upstream", "https_upstream"]
        .iter()
        .any(|name| viewer.allows(name));
    let actions = adds
        .then(|| dialog(viewer, keys::WEB_DNS_SERVER_ADD, "server"))
        .into_iter()
        .collect();
    let region = Region::new(locale).table(table_view(&Servers, &table, locale));
    (region, actions)
}

/// The static records tab.
fn records(state: &DnsState, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let lines = state
        .records()
        .iter()
        .map(|entry| {
            Line::new(vec![
                Cell::code(entry.name().to_owned()),
                value(locale, entry, 0),
            ])
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("dns/records"));
    let actions = viewer
        .allows("static_host")
        .then(|| dialog(viewer, keys::WEB_DNS_RECORD_ADD, "record"))
        .into_iter()
        .collect();
    let region = Region::new(locale).table(table_view(&Records, &table, locale));
    (region, actions)
}

/// The domain lists tab: each list with Add domain.
fn lists(state: &DnsState, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let edits = viewer.allows("fqdn_group");
    let lines = state
        .lists()
        .iter()
        .map(|entry| {
            let line = Line::new(vec![
                Cell::code(entry.name().to_owned()),
                entry.value(0).map_or_else(
                    || Cell::missing(locale, keys::WEB_DNS_NONE),
                    |text| Cell::text(text.to_owned()),
                ),
                Cell::codes(locale, entry.list(0), keys::WEB_DNS_NONE),
                Cell::codes(locale, entry.list(1), keys::WEB_DNS_NONE),
            ]);
            if edits {
                let query = form_urlencoded::Serializer::new(String::new())
                    .append_pair("list", entry.name())
                    .finish();
                let href = viewer.href(&format!("dns/form/entry?{query}"));
                line.with(Act::open(locale, keys::WEB_DNS_ENTRY_ADD, href))
            } else {
                line
            }
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("dns/lists"));
    let actions = edits
        .then(|| dialog(viewer, keys::WEB_DNS_LIST_ADD, "list"))
        .into_iter()
        .collect();
    let region = Region::new(locale).table(table_view(&Lists, &table, locale));
    (region, actions)
}

/// The routes tab; Add route needs a domain list to route.
fn routes(state: &DnsState, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let lines = state
        .routes()
        .iter()
        .map(|entry| {
            Line::new(vec![
                Cell::code(entry.name().to_owned()),
                value(locale, entry, 0),
                value(locale, entry, 1),
            ])
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("dns/routes"));
    let actions = (viewer.allows("route") && !state.lists().is_empty())
        .then(|| dialog(viewer, keys::WEB_DNS_ROUTE_ADD, "route"))
        .into_iter()
        .collect();
    let region = Region::new(locale).table(table_view(&Routes, &table, locale));
    (region, actions)
}
