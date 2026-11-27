//! The interfaces with address translation (NAT) of the port forwarding page.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, nat::read};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::views::{View, allows, unreachable, views};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        read_failure::ReadProblem,
        request::{rendered, with_query},
    },
    routing_page::frame::{Frame, Tab, Visit},
    table::{
        Direction, Sort,
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        rows::{Row, SortKey, Table, TableQuery},
        view::TableView,
    },
};

/// One interface with address translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NatInterface {
    /// The interface.
    name: String,
}

impl NatInterface {
    /// The interface.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

impl Row for NatInterface {
    const COLUMNS: &'static [&'static str] = &["interface"];

    const DEFAULT: Sort = Sort::new("interface", Direction::Ascending);

    fn key(&self, _column: &str) -> SortKey {
        SortKey::text(&self.name)
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
    }
}

/// The interfaces with address translation (`partials/nat_interfaces.html`).
#[derive(Template)]
#[template(path = "partials/nat_interfaces.html")]
pub(crate) struct InterfacesRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// The shown page of interfaces.
    table: TableView,
}

localized!(InterfacesRegion);

impl InterfacesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}

/// The interfaces with address translation on `router`, with Remove when `removable`, in
/// `locale`.
fn interfaces_view(
    router: &str,
    table: &Table<NatInterface>,
    (removable, locale): (bool, Locale),
) -> TableView {
    let class = "table routing-table routing-table--narrow";
    let mut view = TableView::filtered(class, table, (locale, keys::WEB_NAT_INTERFACES_EMPTY))
        .head(Head::sorted(
            tr(locale, keys::WEB_ROUTING_COL_INTERFACE, None),
            table.header("interface"),
        ));
    if removable {
        view = view.head(Head::hidden(tr(locale, keys::WEB_CLIENTS_ACTIONS, None)));
    }
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("nat-interface-{}", index.saturating_add(1));
        let mut cells = vec![
            Cell::code(row.name().to_owned())
                .attr("id", id.clone())
                .head(),
        ];
        if removable {
            let href = with_query(
                &format!("/ui/r/{router}/nat/interface/remove"),
                &[("name", row.name())],
            );
            let remove = Act::opens(tr(locale, keys::WEB_ROUTING_REMOVE, None), href).danger();
            cells.push(Cell::acts(Layout::Inline, vec![remove], id).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}

/// `GET /ui/r/{router}/nat/interfaces`: the interfaces with address translation.
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn interfaces(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
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
    let mut frame = Frame::new(shell, &router, Tab::Nat)
        .with_views(keys::WEB_NAT_VIEWS, views(&router, View::Interfaces));
    let region = match reading {
        Ok((facts, domain)) => {
            let allowed = allows(&user, &router, facts.catalog(), "interface");
            if allowed {
                let href = format!("/ui/r/{router}/nat/interface/new");
                frame = frame.with_add(href, keys::WEB_NAT_INTERFACE_ADD);
            }
            interfaces_region(&domain, (&router, &query), (allowed, locale))
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The NAT interfaces region on `router` for `query` in `locale`, with Remove when
/// `removable`.
///
/// # Errors
///
/// Returns why the router did not answer.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn interfaces_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (removable, locale): (bool, Locale),
) -> Result<InterfacesRegion, ReadProblem> {
    let names = nat_interfaces(domain).await?;
    let rows = names
        .into_iter()
        .map(|name| NatInterface { name })
        .collect();
    let table = Table::new(rows, query, format!("/ui/r/{router}/nat/interfaces"));
    Ok(InterfacesRegion {
        shell: fragment_shell(locale),
        oob: false,
        table: interfaces_view(router, &table, (removable, locale)),
    })
}

/// The interfaces with address translation.
///
/// # Errors
///
/// Returns why the router did not answer.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn nat_interfaces(domain: &RouterCtx) -> Result<Vec<String>, ReadProblem> {
    let rows = read::interfaces(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.interface.or_else(|| row.command.first().cloned()))
        .collect())
}
