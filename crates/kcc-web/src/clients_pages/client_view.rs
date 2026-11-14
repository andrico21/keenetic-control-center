//! The clients table as the browser asked for it.
//!
//! The state and connection filters sit next to the table's own text filter, sort and
//! page; the region renders the table with all of them kept in its links.

use askama::Template;
use axum::{extract::Query, http::Uri};
use fluent_bundle::FluentArgs;
use kcc_domain::clients::Client;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;

use super::{
    client_act::NAMES,
    client_rows::{ClientRow, Medium, Presence},
    client_table,
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    table::{
        SortHeader,
        head::Head,
        pager::Pager,
        rows::{Table, TableQuery},
        view::TableView,
    },
};

/// The filters of the clients page as the query carries them: `state` and `link`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct FilterQuery {
    /// `online` or `offline`.
    state: Option<String>,
    /// `wired` or `wireless`.
    link: Option<String>,
}

/// The page's own filters; an unknown value means no filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Filters {
    /// Only clients in this state.
    presence: Option<Presence>,
    /// Only clients connected this way.
    medium: Option<Medium>,
}

impl Filters {
    /// The filters `query` asks for.
    fn parse(query: &FilterQuery) -> Self {
        Self {
            presence: match query.state.as_deref() {
                Some("online") => Some(Presence::Online),
                Some("offline") => Some(Presence::Offline),
                _ => None,
            },
            medium: match query.link.as_deref() {
                Some("wired") => Some(Medium::Wired),
                Some("wireless") => Some(Medium::Wireless),
                _ => None,
            },
        }
    }

    /// The `state` value, empty for any.
    pub(crate) const fn state(self) -> &'static str {
        match self.presence {
            Some(Presence::Online) => "online",
            Some(Presence::Offline) => "offline",
            None => "",
        }
    }

    /// The `link` value, empty for any.
    pub(crate) const fn link(self) -> &'static str {
        match self.medium {
            Some(Medium::Wired) => "wired",
            Some(Medium::Wireless) => "wireless",
            None => "",
        }
    }

    /// The query parameters that keep these filters.
    fn pairs(self) -> Vec<(&'static str, &'static str)> {
        [("state", self.state()), ("link", self.link())]
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .collect()
    }

    /// Whether `row` passes the filters.
    fn admits(self, row: &ClientRow) -> bool {
        self.presence
            .is_none_or(|presence| presence == row.presence())
            && self.medium.is_none_or(|medium| medium == row.medium())
    }
}

/// What the browser asked the clients table for: the text filter, sort and page, and the
/// page's own filters.
#[derive(Debug, Default)]
pub(crate) struct View {
    /// `?q=&sort=&dir=&page=`.
    query: TableQuery,
    /// `?state=&link=`.
    filters: Filters,
}

impl View {
    /// The view `query` and `filters` ask for.
    pub(crate) fn new(query: TableQuery, filters: &FilterQuery) -> Self {
        Self {
            query,
            filters: Filters::parse(filters),
        }
    }

    /// The view of the page at `uri`, such as htmx's `HX-Current-URL`; the default view
    /// without one.
    pub(crate) fn of_page(uri: Option<&Uri>) -> Self {
        let Some(page) = uri else {
            return Self::default();
        };
        Self::new(
            Query::<TableQuery>::try_from_uri(page).map_or_default(|Query(query)| query),
            &Query::<FilterQuery>::try_from_uri(page).map_or_default(|Query(filters)| filters),
        )
    }

    /// The region of `clients` on `router` in `locale` for this view.
    pub(crate) fn region(&self, locale: Locale, router: String, clients: Vec<Client>) -> Region {
        let total = clients.len();
        let rows = clients
            .into_iter()
            .filter_map(|client| ClientRow::new(client, locale))
            .filter(|row| self.filters.admits(row))
            .collect();
        let base = format!("/ui/r/{router}/clients");
        Region {
            shell: fragment_shell(locale),
            router,
            table: Table::new(rows, &self.query, base),
            filters: self.filters,
            total,
            controls: Controls::default(),
            oob: false,
        }
    }
}

/// The filter form and the table of the clients page; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/clients_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The shown page of filtered, sorted rows.
    table: Table<ClientRow>,
    /// The page's own filters.
    filters: Filters,
    /// Clients the router reported.
    total: usize,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);

impl Region {
    /// Shows the row actions `controls` allow.
    pub(crate) fn with_controls(mut self, controls: Controls) -> Self {
        self.controls = controls;
        self
    }

    /// The region as an out-of-band replacement of the page's.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The header cell of `column`, keeping the text filter and the page's filters.
    fn header(&self, column: &'static str) -> SortHeader {
        let mut keep = self.filters.pairs();
        if !self.table.filter().is_empty() {
            keep.insert(0, ("q", self.table.filter()));
        }
        self.table
            .sort()
            .header_keeping(self.table.base(), column, &keep)
    }

    /// The pager, its links keeping the page's filters.
    fn pager(&self) -> KeptPager {
        KeptPager {
            pager: self.table.pager().clone(),
            kept: self.filters.pairs().into_iter().fold(
                String::new(),
                |mut kept, (name, value)| {
                    kept.push('&');
                    kept.push_str(name);
                    kept.push('=');
                    kept.push_str(value);
                    kept
                },
            ),
        }
    }

    /// Whether any filter is set, which offers Clear.
    fn filtered(&self) -> bool {
        !self.table.filter().is_empty() || self.filters != Filters::default()
    }

    /// "4 of 6": the clients shown and the clients reported.
    fn count(&self) -> String {
        let mut args = FluentArgs::new();
        args.set("count", self.table.matched());
        args.set("total", self.total);
        tr(self.shell.locale(), keys::WEB_KIT_TABLE_COUNT, Some(&args))
    }

    /// Why the table is empty, when it is.
    fn empty(&self) -> Option<MessageKey> {
        match (self.table.rows().is_empty(), self.total) {
            (false, _) => None,
            (true, 0) => Some(keys::WEB_KIT_TABLE_EMPTY),
            (true, _) => Some(keys::WEB_KIT_TABLE_NO_MATCH),
        }
    }

    /// The clients table, or why it is empty.
    fn clients(&self) -> TableView {
        let locale = self.shell.locale();
        if let Some(message) = self.empty() {
            return TableView::new(client_table::CLASS)
                .blank("page__text", tr(locale, message, None));
        }
        let heads = client_table::COLUMNS
            .iter()
            .map(|(column, key)| Head::sorted(tr(locale, *key, None), self.header(column)))
            .collect();
        let actions = NAMES.iter().any(|name| self.controls.allows(name));
        let viewer = (self.router.as_str(), &self.controls, locale);
        client_table::view(heads, &self.table, (viewer, actions))
    }
}

/// The table's pager with the page's filters appended to its links.
pub(crate) struct KeptPager {
    /// The table's pager.
    pager: Pager,
    /// `&state=..&link=..` for the filters set.
    kept: String,
}

impl KeptPager {
    /// Whether the table has more than one page.
    pub(crate) const fn multiple(&self) -> bool {
        self.pager.multiple()
    }

    /// The previous page's link.
    pub(crate) fn previous(&self) -> Option<String> {
        self.pager.previous().map(|href| self.keep(href))
    }

    /// The next page's link.
    pub(crate) fn next(&self) -> Option<String> {
        self.pager.next().map(|href| self.keep(href))
    }

    /// "Page 2 of 3" in `locale`.
    pub(crate) fn status(&self, locale: Locale) -> String {
        self.pager.status(locale)
    }

    /// `href` with the page's filters appended.
    fn keep(&self, mut href: String) -> String {
        href.push_str(&self.kept);
        href
    }
}

#[cfg(test)]
#[path = "client_view_tests.rs"]
mod tests;
