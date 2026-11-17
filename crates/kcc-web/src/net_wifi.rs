//! The Wi-Fi page at `/ui/r/{router}/wifi`.
//!
//! The radios with their band, channel, width, power and country; the access points with
//! their network name, security, whether a Wi-Fi password is set, whether the name is
//! hidden, their state, schedule and segment; and the connected devices with their signal
//! in a filterable, sortable table of 50 rows a page. Settings opens a radio's or an
//! access point's settings (`net_wifi_settings`), Enable and Disable are shown where the
//! role may change them.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{DomainError, RouterCtx, wifi};
use kcc_i18n::{bundle::MessageKey, keys};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    markup::Rendered,
    net_pages::{Call, Tab, Tabs, Viewer},
    net_wifi_rows::{access_points, radios},
    net_wifi_stations::stations,
    net_wifi_tables::{points_view, radios_view, stations_view},
    page::{Localize as _, Shell},
    page_kit::{
        context,
        context::{Caller, fragment_shell},
        family::Family,
        gate::Controls,
        request::rendered,
    },
    table::{
        rows::{Table, TableQuery},
        view::TableView,
    },
};

/// The page.
#[derive(Template)]
#[template(path = "pages/net_wifi.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The network pages' tab bar.
    tabs: Tabs,
    /// Radios, access points and devices, when the router answered.
    listing: Option<Listing>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
}

localized!(Page);

/// `GET /ui/r/{router}/wifi`: radios, access points and connected devices.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Tab::Wifi.section(), Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tabs::new(&router, Tab::Wifi),
        router: router.clone(),
        listing: None,
        problem: None,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(wifi::DESCRIPTOR.write_ops, Some(facts.catalog()));
            let viewer = Call::new(&state, &user, &router, &headers).viewer(controls);
            match Listing::read(&domain, viewer, &query).await {
                Ok(listing) => page.listing = Some(listing),
                Err(error) => {
                    tracing::warn!(%error, "Wi-Fi page: router read failed");
                    page.problem = Some(Family::Changes.unreachable());
                }
            }
        }
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}

/// The radios, access points and devices read back after a change, out of band, keeping
/// the device table's filter, order and page.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn refreshed(call: Call<'_>, domain: &RouterCtx) -> Option<Rendered> {
    let controls = Controls::new(call.user().role(), call.router())
        .with_operations(wifi::DESCRIPTOR.write_ops, Some(&domain.catalog));
    let listing = Listing::read(domain, call.viewer(controls), &call.shown_query())
        .await
        .inspect_err(|error| tracing::warn!(%error, "Wi-Fi read-back failed"))
        .ok()?;
    rendered(&listing.out_of_band())
}

/// Radios, access points and devices; a change sends them again out of band.
#[derive(Template)]
#[template(path = "partials/net_wifi_region.html")]
struct Listing {
    /// Locale carrier.
    shell: Shell,
    /// The radios.
    radios: TableView,
    /// The access points.
    points: TableView,
    /// The page of devices shown.
    table: TableView,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Listing);
fragment!(Listing);

impl Listing {
    /// Reads the router of `domain` and cuts the page of devices `query` asks for.
    ///
    /// # Errors
    ///
    /// Returns the router's error.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    async fn read(
        domain: &RouterCtx,
        viewer: Viewer,
        query: &TableQuery,
    ) -> Result<Self, DomainError> {
        let found_radios = radios(domain).await?;
        let points = access_points(domain).await?;
        let devices = stations(domain).await?;
        let (router, locale, controls) = viewer.into_parts();
        let table = Table::new(devices, query, format!("/ui/r/{router}/wifi"));
        Ok(Self {
            shell: fragment_shell(locale),
            radios: radios_view(&router, &found_radios, locale),
            points: points_view(&router, &points, (&controls, locale)),
            table: stations_view(&table, locale),
            oob: false,
        })
    }

    /// The region as an out-of-band replacement of the page's.
    const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The radios table.
    const fn radio_table(&self) -> &TableView {
        &self.radios
    }

    /// The access points table.
    const fn point_table(&self) -> &TableView {
        &self.points
    }
}
