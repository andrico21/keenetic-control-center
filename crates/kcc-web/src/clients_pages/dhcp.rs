//! The DHCP views of one router: pools, static leases, active leases and the ARP table,
//! each a filtered, sorted, paged table with the changes the role may make.

use askama::Template;
use axum::{
    extract::Query,
    http::{HeaderMap, Uri},
};
use kcc_domain::{Result as DomainResult, RouterCtx, clients, dhcp};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use url::form_urlencoded::{Serializer, byte_serialize};

use super::{
    TabLink,
    dhcp_rows::{HostRow, PoolRow, names},
    dhcp_table,
};
use crate::{
    authz::CurrentUser,
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        gate::Controls,
        request::{rendered, shown_uri},
    },
    table::{
        rows::{Table, TableQuery},
        view::TableView,
    },
};

/// One view of the DHCP page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DhcpView {
    /// The pools.
    #[default]
    Pools,
    /// The static leases.
    Leases,
    /// The leases handed out now.
    Bindings,
    /// The ARP table.
    Arp,
}

impl DhcpView {
    /// Every view, in order.
    const ALL: [Self; 4] = [Self::Pools, Self::Leases, Self::Bindings, Self::Arp];

    /// The view's path on `router`.
    pub(crate) fn path(self, router: &str) -> String {
        match self {
            Self::Pools => format!("/ui/r/{router}/dhcp"),
            Self::Leases => format!("/ui/r/{router}/dhcp/leases"),
            Self::Bindings => format!("/ui/r/{router}/dhcp/bindings"),
            Self::Arp => format!("/ui/r/{router}/dhcp/arp"),
        }
    }

    /// The view's label.
    const fn label(self) -> MessageKey {
        match self {
            Self::Pools => keys::WEB_DHCP_POOLS,
            Self::Leases => keys::WEB_DHCP_LEASES,
            Self::Bindings => keys::WEB_DHCP_BINDINGS,
            Self::Arp => keys::WEB_DHCP_ARP,
        }
    }

    /// The view the page at `uri` on `router` shows, such as htmx's `HX-Current-URL`.
    pub(crate) fn of_page(uri: &Uri, router: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|view| view.path(router) == uri.path())
    }

    /// The links to every view on `router`, this one marked current.
    pub(crate) fn links(self, router: &str) -> Vec<TabLink> {
        Self::ALL
            .into_iter()
            .map(|view| TabLink::new(view.path(router), view.label(), view == self))
            .collect()
    }
}

/// The rows of one view.
pub(crate) enum Listing {
    /// Pools.
    Pools(Table<PoolRow>),
    /// Static leases, active leases or ARP neighbours.
    Hosts(Table<HostRow>),
}

/// The table region of a DHCP view; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/dhcp_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The view shown.
    view: DhcpView,
    /// Its rows.
    listing: Listing,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);
fragment!(Region);

/// A DHCP view as the browser asked for it: the view and its filter, sort and page.
#[derive(Debug, Default)]
pub(crate) struct Shown {
    /// The view.
    view: DhcpView,
    /// `?q=&sort=&dir=&page=`.
    query: TableQuery,
}

impl Shown {
    /// `view` as `query` asks.
    pub(crate) const fn new(view: DhcpView, query: TableQuery) -> Self {
        Self { view, query }
    }

    /// The view of the page the browser shows on `router`, from htmx's `HX-Current-URL`;
    /// `fallback` without one.
    pub(crate) fn of_page(headers: &HeaderMap, router: &str, fallback: DhcpView) -> Self {
        let Some(page) = shown_uri(headers) else {
            return Self::new(fallback, TableQuery::default());
        };
        Self::new(
            DhcpView::of_page(&page, router).unwrap_or(fallback),
            Query::<TableQuery>::try_from_uri(&page).map_or_default(|Query(query)| query),
        )
    }

    /// The region of this view on `router`, read through `domain`, in `locale`.
    ///
    /// # Errors
    ///
    /// Returns the read's failure.
    // cancel-safe: reads only.
    pub(crate) async fn region(
        &self,
        domain: &RouterCtx,
        router: &str,
        locale: Locale,
    ) -> DomainResult<Region> {
        let base = self.view.path(router);
        let listing = if self.view == DhcpView::Pools {
            let pools = dhcp::read_pools(domain).await?;
            let rows = pools
                .into_iter()
                .filter_map(|pool| PoolRow::new(pool, locale));
            Listing::Pools(Table::new(rows.collect(), &self.query, base))
        } else {
            let known = names(clients::read_clients(domain).await.unwrap_or_default());
            let rows: Vec<HostRow> = match self.view {
                DhcpView::Leases => dhcp::read_static_leases(domain)
                    .await?
                    .into_iter()
                    .filter_map(|lease| HostRow::lease(lease, &known))
                    .collect(),
                DhcpView::Bindings => dhcp::read_bindings(domain)
                    .await?
                    .into_iter()
                    .filter_map(|binding| HostRow::binding(binding, &known, locale))
                    .collect(),
                DhcpView::Arp | DhcpView::Pools => dhcp::read_neighbours(domain)
                    .await?
                    .into_iter()
                    .filter_map(|neighbour| HostRow::neighbour(neighbour, &known))
                    .collect(),
            };
            Listing::Hosts(Table::new(rows, &self.query, base))
        };
        Ok(Region {
            shell: fragment_shell(locale),
            router: router.to_owned(),
            view: self.view,
            listing,
            controls: Controls::default(),
            oob: false,
        })
    }

    /// This view read back after a change by `user` on `router`, with the controls the
    /// role may use, rendered for an out-of-band swap.
    // cancel-safe: reads only.
    pub(crate) async fn read_back(
        &self,
        domain: &RouterCtx,
        user: &CurrentUser,
        router: &str,
    ) -> Option<Rendered> {
        let controls = Controls::new(user.role(), router)
            .with_operations(dhcp::DESCRIPTOR.write_ops, Some(&domain.catalog));
        let region = self
            .region(domain, router, user.locale())
            .await
            .inspect_err(|error| tracing::warn!(%error, "DHCP read-back failed"))
            .ok()?;
        rendered(&region.with_controls(controls).out_of_band())
    }
}

impl Region {
    /// Shows the changes `controls` allow.
    pub(crate) fn with_controls(mut self, controls: Controls) -> Self {
        self.controls = controls;
        self
    }

    /// The region as an out-of-band replacement of the page's.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The table of the view, or the note in its place.
    fn table_view(&self) -> TableView {
        let locale = self.shell.locale();
        match &self.listing {
            Listing::Pools(table) => {
                let edit = |row: &PoolRow| self.edit_url(row);
                let link: dhcp_table::RowLink<'_, PoolRow> =
                    self.controls.allows("pool").then_some(&edit);
                dhcp_table::pools(table, link, locale)
            }
            Listing::Hosts(table) => {
                let reserve = |row: &HostRow| self.reserve_url(row);
                let link: dhcp_table::RowLink<'_, HostRow> = self.reserve().then_some(&reserve);
                dhcp_table::hosts(table, ((self.detailed(), self.expiring()), link), locale)
            }
        }
    }

    /// Whether the hosts carry an interface and a state: active leases and ARP.
    fn detailed(&self) -> bool {
        self.view != DhcpView::Leases
    }

    /// Whether the hosts carry the time left on their lease.
    fn expiring(&self) -> bool {
        self.view == DhcpView::Bindings
    }

    /// Whether an active lease may be made static.
    fn reserve(&self) -> bool {
        self.view == DhcpView::Bindings && self.controls.allows("static_lease")
    }

    /// The pool editor of `row`.
    fn edit_url(&self, row: &PoolRow) -> String {
        let name: String = byte_serialize(row.name().as_bytes()).collect();
        format!("/ui/r/{}/dhcp/pools/edit?name={name}", self.router)
    }

    /// The static lease form pre-filled with the host of `row`.
    fn reserve_url(&self, row: &HostRow) -> String {
        let mut query = Serializer::new(String::new());
        let _: &mut Serializer<'_, String> = query.append_pair("mac", row.mac());
        if let Some(address) = row.address() {
            let _: &mut Serializer<'_, String> = query.append_pair("address", address);
        }
        format!("/ui/r/{}/dhcp/leases/new?{}", self.router, query.finish())
    }
}
