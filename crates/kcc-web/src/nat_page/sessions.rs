//! The active connections of the port forwarding page.
//!
//! The router sends at most 200 rows a page (`show ip nat` with an offset and a limit);
//! the page shows one of them, sorted and filtered within it, with links to the previous
//! page and, when the router sent a full page, the next one.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_domain::nat::{
    model::NatSession,
    read::{PAGE_SIZE, sessions_page},
};
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};
use serde::Deserialize;

use super::{
    session_rows::Session,
    views::{View, views},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        request::{rendered, with_query},
    },
    routing_page::frame::{Frame, Tab, Visit, protocol_text},
    table::{
        Direction, Sort, SortHeader,
        cells::Cell,
        rows::Row as _,
        view::{Head, TableView},
    },
};

/// The last page a link may ask for, so an offset stays small.
const LAST_PAGE: usize = 10_000;

/// Longest filter text read, in characters.
const FILTER_CHARS: usize = 100;

/// The query of the connections view: `?q=&sort=&dir=&page=`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct SessionsQuery {
    /// Filter text.
    #[serde(default, rename = "q")]
    filter: Option<String>,
    /// Sorted column.
    #[serde(default)]
    sort: Option<String>,
    /// Sort direction.
    #[serde(default)]
    dir: Option<String>,
    /// Router page, from 1.
    #[serde(default)]
    page: Option<String>,
}

/// One router page of connections, sorted and filtered within it
/// (`partials/nat_sessions.html`).
#[derive(Template)]
#[template(path = "partials/nat_sessions.html")]
struct SessionsRegion {
    /// Locale carrier.
    shell: Shell,
    /// The rows shown.
    rows: Vec<Session>,
    /// Rows the router sent for the page.
    sent: usize,
    /// The sort order.
    sort: Sort,
    /// The filter text; empty for none.
    filter: String,
    /// The router page, from 1.
    page: usize,
    /// Path of the view.
    base: String,
}

localized!(SessionsRegion);

impl SessionsRegion {
    /// The sort header of `column`, keeping the filter and the page.
    fn header(&self, column: &'static str) -> SortHeader {
        let page = self.page.to_string();
        let mut keep = vec![("page", page.as_str())];
        if !self.filter.is_empty() {
            keep.insert(0, ("q", self.filter.as_str()));
        }
        self.sort.header_keeping(&self.base, column, &keep)
    }

    /// The link to router page `page`, keeping the filter and the sort.
    fn page_link(&self, page: usize) -> String {
        let number = page.to_string();
        let mut pairs = vec![
            ("sort", self.sort.column()),
            ("dir", self.sort.direction().param()),
            ("page", number.as_str()),
        ];
        if !self.filter.is_empty() {
            pairs.insert(0, ("q", self.filter.as_str()));
        }
        with_query(&self.base, &pairs)
    }

    /// The shown page without the filter.
    fn unfiltered(&self) -> String {
        let number = self.page.to_string();
        let pairs = [
            ("sort", self.sort.column()),
            ("dir", self.sort.direction().param()),
            ("page", number.as_str()),
        ];
        with_query(&self.base, &pairs)
    }

    /// Whether there is another page either way.
    const fn multiple(&self) -> bool {
        self.page > 1 || self.sent >= PAGE_SIZE
    }

    /// The previous page's link.
    fn previous(&self) -> Option<String> {
        (self.page > 1).then(|| self.page_link(self.page.saturating_sub(1)))
    }

    /// The next page's link, when the router sent a full page.
    fn next(&self) -> Option<String> {
        (self.sent >= PAGE_SIZE && self.page < LAST_PAGE)
            .then(|| self.page_link(self.page.saturating_add(1)))
    }

    /// "Connections 201 to 400" in `locale`.
    fn status(&self, locale: Locale) -> String {
        let first = self.page.saturating_sub(1).saturating_mul(PAGE_SIZE);
        let mut args = FluentArgs::new();
        args.set("first", first.saturating_add(1).to_string());
        args.set("last", first.saturating_add(self.sent).to_string());
        tr(locale, keys::WEB_NAT_SESSIONS_STATUS, Some(&args))
    }

    /// The table of the shown rows, or why none shows.
    fn table_view(&self) -> TableView {
        let locale = self.shell.locale();
        let mut view = TableView::new("table routing-table nat-sessions");
        if self.rows.is_empty() {
            let shown = if self.filter.is_empty() {
                keys::WEB_NAT_SESSIONS_EMPTY
            } else {
                keys::WEB_KIT_TABLE_NO_MATCH
            };
            return view.blank("page__text", tr(locale, shown, None));
        }
        for (column, key) in [
            ("source", keys::WEB_NAT_COL_SOURCE),
            ("destination", keys::WEB_NAT_COL_DESTINATION),
            ("translated", keys::WEB_NAT_COL_TRANSLATED),
            ("protocol", keys::WEB_ROUTING_COL_PROTOCOL),
            ("interface", keys::WEB_ROUTING_COL_INTERFACE),
            ("state", keys::WEB_NAT_COL_STATE),
            ("received", keys::WEB_NAT_COL_RECEIVED),
            ("sent", keys::WEB_NAT_COL_SENT),
        ] {
            view = view.head(Head::sorted(tr(locale, key, None), self.header(column)));
        }
        let bytes = |value: Option<u64>| {
            Cell::optional(value.map(|count| format::bytes(locale, count))).class("numeric")
        };
        for row in &self.rows {
            let protocol = row.protocol().map(|name| protocol_text(locale, name));
            view = view.row(vec![
                Cell::optional(row.source().map(str::to_owned))
                    .class("mono")
                    .head(),
                Cell::optional(row.destination().map(str::to_owned)).class("mono"),
                Cell::optional(row.translated().map(str::to_owned)).class("mono"),
                Cell::text(protocol.unwrap_or_default()),
                Cell::optional(row.interface().map(str::to_owned)).class("mono"),
                Cell::optional(row.state().map(str::to_owned)),
                bytes(row.received()),
                bytes(row.sent()),
            ]);
        }
        view
    }
}

/// `GET /ui/r/{router}/nat/sessions?q=&sort=&dir=&page=`: one router page of connections.
pub(crate) async fn sessions(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<SessionsQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Nat).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let frame = Frame::new(shell, &router, Tab::Nat)
        .with_views(keys::WEB_NAT_VIEWS, views(&router, View::Sessions));
    let page = query
        .page
        .as_deref()
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, LAST_PAGE);
    let region = match reading {
        Ok((_facts, domain)) => {
            let offset = page.saturating_sub(1).saturating_mul(PAGE_SIZE);
            match sessions_page(&domain, offset).await {
                Ok(found) => Ok(rendered(&region(
                    &found.rows,
                    &query,
                    (&router, page, locale),
                ))),
                Err(error) => {
                    tracing::warn!(%error, "port forwarding page: connections unavailable");
                    Err(keys::WEB_KIT_UNREACHABLE)
                }
            }
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The region of the router `rows` of `page` on `router` for `query`, in `locale`.
fn region(
    rows: &[NatSession],
    query: &SessionsQuery,
    (router, page, locale): (&str, usize, Locale),
) -> SessionsRegion {
    let filter: String = query
        .filter
        .as_deref()
        .unwrap_or_default()
        .trim()
        .chars()
        .take(FILTER_CHARS)
        .collect();
    let needle = filter.to_lowercase();
    let sort = Sort::parse(
        query.sort.as_deref(),
        query.dir.as_deref(),
        Session::COLUMNS,
        Session::DEFAULT,
    );
    let mut shown: Vec<Session> = rows
        .iter()
        .map(Session::from_row)
        .filter(|session| needle.is_empty() || session.matches(&needle))
        .collect();
    shown.sort_by(|left, right| {
        let order = left.key(sort.column()).cmp(&right.key(sort.column()));
        match sort.direction() {
            Direction::Ascending => order,
            Direction::Descending => order.reverse(),
        }
    });
    SessionsRegion {
        shell: fragment_shell(locale),
        rows: shown,
        sent: rows.len(),
        sort,
        filter,
        page,
        base: format!("/ui/r/{router}/nat/sessions"),
    }
}
