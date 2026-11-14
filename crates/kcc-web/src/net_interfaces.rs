//! The interfaces page at `/ui/r/{router}/network`.
//!
//! Every interface the router reports, in a filterable, sortable table of 50 rows a page
//! with its type, link, state, address and security level. Details opens an interface's
//! drawer (`net_interface_detail`); Enable and Disable are shown where the role may change
//! them (`net_interface_actions`).

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{DomainError, RouterCtx, interfaces};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    net_change::{rendered, with_query},
    net_interface_line::Line,
    net_pages::{Call, Tab, Tabs, Viewer},
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller, fragment_shell},
        family::Family,
        gate::Controls,
    },
    table::rows::{Table, TableQuery},
};

/// The page.
#[derive(Template)]
#[template(path = "pages/net_interfaces.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The network pages' tab bar.
    tabs: Tabs,
    /// The interfaces, when the router answered.
    listing: Option<Listing>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
}

localized!(Page);

/// `GET /ui/r/{router}/network`: the interfaces and the controls the role may use.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Tab::Interfaces.section(), Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tabs::new(&router, Tab::Interfaces),
        router: router.clone(),
        listing: None,
        problem: None,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(interfaces::DESCRIPTOR.write_ops, Some(facts.catalog()));
            let viewer = Call::new(&state, &user, &router, &headers).viewer(controls);
            match Listing::read(&domain, viewer, &query).await {
                Ok(listing) => page.listing = Some(listing),
                Err(error) => {
                    tracing::warn!(%error, "interfaces page: router read failed");
                    page.problem = Some(Family::Changes.unreachable());
                }
            }
        }
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}

/// The interfaces table read back after a change, out of band, keeping the page's
/// filter, order and page.
// cancel-safe: reads only.
pub(crate) async fn refreshed(call: Call<'_>, domain: &RouterCtx) -> Option<String> {
    let controls = Controls::new(call.user().role(), call.router())
        .with_operations(interfaces::DESCRIPTOR.write_ops, Some(&domain.catalog));
    let listing = Listing::read(domain, call.viewer(controls), &call.shown_query())
        .await
        .inspect_err(|error| tracing::warn!(%error, "interfaces read-back failed"))
        .ok()?;
    rendered(&listing.out_of_band())
}

/// The interfaces table with its filter and pager; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/net_interfaces_region.html")]
struct Listing {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The page of interfaces shown.
    table: Table<Line>,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Listing);

impl Listing {
    /// Reads the interfaces of the router of `domain` and cuts the page `query` asks for.
    ///
    /// # Errors
    ///
    /// Returns the router's error.
    // cancel-safe: reads only.
    async fn read(
        domain: &RouterCtx,
        viewer: Viewer,
        query: &TableQuery,
    ) -> Result<Self, DomainError> {
        let found = interfaces::read_interfaces(domain).await?;
        let (router, locale, controls) = viewer.into_parts();
        let lines = found
            .into_iter()
            .map(|(id, interface)| Line::new(id, &interface))
            .collect();
        Ok(Self {
            shell: fragment_shell(locale),
            table: Table::new(lines, query, format!("/ui/r/{router}/network")),
            router,
            controls,
            oob: false,
        })
    }

    /// The region as an out-of-band replacement of the page's.
    const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// "3 of 12" while a filter hides rows.
    fn count(&self) -> Option<String> {
        (!self.table.filter().is_empty()).then(|| {
            let mut args = FluentArgs::new();
            args.set("count", self.table.matched());
            args.set("total", self.table.total());
            tr(self.shell.locale(), keys::WEB_KIT_TABLE_COUNT, Some(&args))
        })
    }

    /// The drawer of `line`.
    fn detail_url(&self, line: &Line) -> String {
        with_query(
            &format!("/ui/r/{}/network/detail", self.router),
            &[("name", line.id())],
        )
    }

    /// Enable or Disable for `line`, when the role may run it: the address and the
    /// localized label.
    fn state_action(&self, line: &Line) -> Option<(String, String)> {
        let (operation, label) = if line.enabled() == Some(false) {
            ("up", keys::WEB_NETWORK_ENABLE)
        } else {
            ("down", keys::WEB_NETWORK_DISABLE)
        };
        self.controls.allows(operation).then(|| {
            let href = with_query(
                &format!("/ui/r/{}/network/state", self.router),
                &[("name", line.id()), ("state", operation)],
            );
            (href, tr(self.shell.locale(), label, None))
        })
    }
}
