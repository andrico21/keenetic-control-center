//! The interfaces with address translation (NAT) of the port forwarding page.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, nat::read};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::views::{View, allows, unreachable, views};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        request::{rendered, with_query},
    },
    routing_page::frame::{Frame, Tab, Visit},
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
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
    /// Router profile id.
    router: String,
    /// The shown page of interfaces.
    table: Table<NatInterface>,
    /// Whether the role may remove them.
    removable: bool,
}

localized!(InterfacesRegion);

impl InterfacesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The address of the removal dialog of `row`.
    fn remove_url(&self, row: &NatInterface) -> String {
        with_query(
            &format!("/ui/r/{}/nat/interface/remove", self.router),
            &[("name", row.name())],
        )
    }
}

/// `GET /ui/r/{router}/nat/interfaces`: the interfaces with address translation.
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
// cancel-safe: reads only.
pub(crate) async fn interfaces_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (removable, locale): (bool, Locale),
) -> Result<InterfacesRegion, MessageKey> {
    let names = nat_interfaces(domain).await?;
    let rows = names
        .into_iter()
        .map(|name| NatInterface { name })
        .collect();
    Ok(InterfacesRegion {
        shell: fragment_shell(locale),
        oob: false,
        router: router.to_owned(),
        table: Table::new(rows, query, format!("/ui/r/{router}/nat/interfaces")),
        removable,
    })
}

/// The interfaces with address translation.
///
/// # Errors
///
/// Returns why the router did not answer.
// cancel-safe: reads only.
pub(crate) async fn nat_interfaces(domain: &RouterCtx) -> Result<Vec<String>, MessageKey> {
    let rows = read::interfaces(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.interface.or_else(|| row.command.first().cloned()))
        .collect())
}
