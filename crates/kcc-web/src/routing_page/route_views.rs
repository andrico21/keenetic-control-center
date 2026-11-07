//! The static routes and the routing table of one address family, each a filtered,
//! sorted table of 50 rows a page.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{
    RouterCtx,
    routing::{descriptor::DESCRIPTOR, model::RouteTableEntry, read},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{
    frame::{Frame, Tab, Visit, view},
    route_rows::{Family, StaticRoute, static_routes},
    table_rows::{TableRoute, table_routes},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    clients_pages::{TabLink, rendered},
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    system_pages::shared::with_query,
    table::rows::{Table, TableQuery},
};

/// The static routes of one family (`partials/routing_static.html`).
#[derive(Template)]
#[template(path = "partials/routing_static.html")]
pub(crate) struct StaticRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// Router profile id.
    router: String,
    /// The shown page of routes.
    table: Table<StaticRoute>,
    /// Whether the family has a metric column (IPv4).
    metrics: bool,
    /// Whether the role may remove routes of this family.
    removable: bool,
}

impl Localize for StaticRegion {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl StaticRegion {
    /// The address of the removal dialog of `route`.
    fn remove_url(&self, route: &StaticRoute) -> String {
        let pairs = route.pairs();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        with_query(
            &format!("/ui/r/{}/routing/route/remove", self.router),
            &borrowed,
        )
    }

    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}

/// The routing table of one family (`partials/routing_table.html`).
#[derive(Template)]
#[template(path = "partials/routing_table.html")]
struct TableRegion {
    /// Locale carrier.
    shell: Shell,
    /// The shown page of routes.
    table: Table<TableRoute>,
}

impl Localize for TableRegion {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/r/{router}/routing`: the IPv4 static routes.
pub(crate) async fn routes_v4(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    statics(&state, visit, &router, (Family::V4, &query)).await
}

/// `GET /ui/r/{router}/routing/ipv6`: the IPv6 static routes.
pub(crate) async fn routes_v6(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    statics(&state, visit, &router, (Family::V6, &query)).await
}

/// `GET /ui/r/{router}/routing/table`: the IPv4 routing table.
pub(crate) async fn table_v4(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    table(&state, visit, &router, (Family::V4, &query)).await
}

/// `GET /ui/r/{router}/routing/table/ipv6`: the IPv6 routing table.
pub(crate) async fn table_v6(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    table(&state, visit, &router, (Family::V6, &query)).await
}

/// The static routes page of `family`.
// cancel-safe: reads only.
async fn statics(
    state: &WebState,
    visit: Visit<'_>,
    router: &str,
    (family, query): (Family, &TableQuery),
) -> Response {
    let (shell, reading) = match visit.open(state, router, Tab::Routes).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let views = switch(router, "routing", family);
    let mut frame =
        Frame::new(shell, router, Tab::Routes).with_views(keys::WEB_ROUTING_FAMILY, views);
    let region = match reading {
        Ok((facts, domain)) => {
            let removable = Controls::new(visit.user().role(), router)
                .with_operations(DESCRIPTOR.write_ops, Some(facts.catalog()))
                .allows(family.operation());
            if removable {
                let href = format!("/ui/r/{router}/routing/route/new?family={}", family.slug());
                frame = frame.with_add(href, keys::WEB_ROUTING_ADD);
            }
            static_region(&domain, (router, family), query, (removable, locale))
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The routing table page of `family`.
// cancel-safe: reads only.
async fn table(
    state: &WebState,
    visit: Visit<'_>,
    router: &str,
    (family, query): (Family, &TableQuery),
) -> Response {
    let (shell, reading) = match visit.open(state, router, Tab::Table).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let views = switch(router, "routing/table", family);
    let frame = Frame::new(shell, router, Tab::Table).with_views(keys::WEB_ROUTING_FAMILY, views);
    let region = match reading {
        Ok((_facts, domain)) => read_table(&domain, family).await.map(|entries| {
            rendered(&TableRegion {
                shell: fragment_shell(locale),
                table: Table::new(
                    table_routes(family, &entries),
                    query,
                    view_path(router, "routing/table", family),
                ),
            })
        }),
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The static routes region of `family` on `router` for `query` in `locale`, with Remove
/// when `removable`.
///
/// # Errors
///
/// Returns why the routes could not be read.
// cancel-safe: reads only.
pub(crate) async fn static_region(
    domain: &RouterCtx,
    (router, family): (&str, Family),
    query: &TableQuery,
    (removable, locale): (bool, Locale),
) -> Result<StaticRegion, MessageKey> {
    let entries = read_table(domain, family).await?;
    Ok(StaticRegion {
        shell: fragment_shell(locale),
        oob: false,
        router: router.to_owned(),
        table: Table::new(
            static_routes(family, &entries),
            query,
            view_path(router, "routing", family),
        ),
        metrics: family == Family::V4,
        removable,
    })
}

/// The routing table of `family`.
///
/// # Errors
///
/// Returns why the router did not answer.
// cancel-safe: reads only.
pub(crate) async fn read_table(
    domain: &RouterCtx,
    family: Family,
) -> Result<Vec<RouteTableEntry>, MessageKey> {
    let read = match family {
        Family::V4 => read::ipv4_table(domain).await,
        Family::V6 => read::ipv6_table(domain).await,
    };
    read.map_err(|error| {
        tracing::warn!(%error, "routing page: route table unavailable");
        keys::WEB_KIT_UNREACHABLE
    })
}

/// The path of the `base` view (`routing` or `routing/table`) of `family` on `router`.
fn view_path(router: &str, base: &str, family: Family) -> String {
    match family {
        Family::V4 => format!("/ui/r/{router}/{base}"),
        Family::V6 => format!("/ui/r/{router}/{base}/ipv6"),
    }
}

/// The IPv4 and IPv6 views of `base`, `shown` current.
fn switch(router: &str, base: &str, shown: Family) -> Vec<TabLink> {
    [Family::V4, Family::V6]
        .into_iter()
        .map(|family| {
            view(
                view_path(router, base, family),
                family.label(),
                family == shown,
            )
        })
        .collect()
}
