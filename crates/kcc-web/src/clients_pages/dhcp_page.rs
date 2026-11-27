//! The DHCP page routes: the pools at `/ui/r/{router}/dhcp` and the other views at
//! `/ui/r/{router}/dhcp/{view}`, each with the primary action the role may use.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::dhcp;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    Tab, TabLink,
    dhcp::{DhcpView, Region, Shown},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller},
        family::Family,
        gate::Controls,
        read_failure::{ReadProblem, domain_problem},
    },
    table::rows::TableQuery,
};

/// A DHCP view page.
#[derive(Template)]
#[template(path = "pages/dhcp.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The local network tabs.
    tabs: Vec<TabLink>,
    /// The DHCP views.
    views: Vec<TabLink>,
    /// The view's primary action: its dialog and its label.
    add: Option<(String, MessageKey)>,
    /// The table, when the router answered.
    region: Option<Region>,
    /// Why the router could not be read.
    problem: Option<ReadProblem>,
}

localized!(Page);

/// The parts of a request every DHCP view uses.
struct Visit<'request> {
    /// Web services.
    state: &'request WebState,
    /// Request headers, for the shell.
    headers: &'request HeaderMap,
    /// The session, for the shell.
    current: &'request CurrentSession,
    /// The signed-in user.
    user: &'request CurrentUser,
}

impl Visit<'_> {
    /// The page of `view` on `router`, as `query` asks.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    async fn show(self, view: DhcpView, router: String, query: TableQuery) -> Response {
        let shell = Caller::new(self.headers, self.current, self.user)
            .shell(self.state, Section::Clients, Some(&router))
            .await;
        let target = match context::target(self.state, self.user, &router).await {
            Ok(found) => found,
            Err(refusal) => return refusal.page(shell),
        };
        let mut page = Page {
            shell,
            tabs: Tab::Dhcp.links(&router),
            views: view.links(&router),
            router: router.clone(),
            add: None,
            region: None,
            problem: None,
        };
        let (facts, domain) = match target.context(self.state).await {
            Ok(found) => found,
            Err(error) => {
                page.problem = Some(error.problem(Family::Changes));
                return errors::render(&page);
            }
        };
        let controls = Controls::new(self.user.role(), &router)
            .with_operations(dhcp::DESCRIPTOR.write_ops, Some(facts.catalog()));
        page.add = match view {
            DhcpView::Pools if controls.allows("pool") => Some((
                format!("/ui/r/{router}/dhcp/pools/edit"),
                keys::WEB_DHCP_POOL_ADD,
            )),
            DhcpView::Leases if controls.allows("static_lease") => Some((
                format!("/ui/r/{router}/dhcp/leases/new"),
                keys::WEB_DHCP_LEASE_ADD,
            )),
            DhcpView::Pools | DhcpView::Leases | DhcpView::Bindings | DhcpView::Arp => None,
        };
        let shown = Shown::new(view, query);
        match shown.region(&domain, &router, self.user.locale()).await {
            Ok(region) => page.region = Some(region.with_controls(controls)),
            Err(error) => {
                tracing::warn!(%error, "DHCP page: the router could not be read");
                page.problem = Some(domain_problem(&error));
            }
        }
        errors::render(&page)
    }
}

/// `GET /ui/r/{router}/dhcp`: the pools.
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn pools(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit {
        state: &state,
        headers: &headers,
        current: &current,
        user: &user,
    };
    visit.show(DhcpView::Pools, router, query).await
}

/// `GET /ui/r/{router}/dhcp/{view}`: the static leases (`leases`), the leases handed out
/// now (`bindings`) or the ARP table (`arp`); 404 for any other view.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn view(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit {
        state: &state,
        headers: &headers,
        current: &current,
        user: &user,
    };
    let chosen = match slug.as_str() {
        "leases" => DhcpView::Leases,
        "bindings" => DhcpView::Bindings,
        "arp" => DhcpView::Arp,
        _ => {
            let shell = Caller::new(&headers, &current, &user)
                .shell(&state, Section::Clients, Some(&router))
                .await;
            return errors::response(Kind::NotFound, shell);
        }
    };
    visit.show(chosen, router, query).await
}
