//! The network pages of one router and what they share.
//!
//! The pages are the interfaces at `/ui/r/{router}/network`, the internet connections at
//! `/ui/r/{router}/internet`, Wi-Fi at `/ui/r/{router}/wifi` and the mesh at
//! `/ui/r/{router}/mesh`.
//!
//! Interface, connection and member names never appear in a path segment: they travel in
//! the query string (`?name=`) or the form body, are parsed as `ObjectName` at the boundary
//! (`net_change::Params`) and reach the router only inside request bodies.
//!
//! Routes (route table: `Read` and the router scope; every change re-checks the
//! permissions of its operation):
//!
//! - `GET /ui/r/{router}/network`: the interfaces; `GET .../network/detail?name=`: one
//!   interface's drawer; `POST .../network/state`: Enable or Disable;
//!   `GET|POST .../network/{description,security-level}`: their dialogs and changes.
//! - `GET /ui/r/{router}/internet`: the internet connections;
//!   `GET|POST .../internet/{create,address,delete}` and `.../internet/edit/{setting}`:
//!   their dialogs and changes; `GET .../internet/settings?name=`: one connection's
//!   settings; `POST .../internet/{default-route,order}`: PPP's default route and the
//!   priority order.
//! - `GET /ui/r/{router}/wifi`: radios, access points and devices;
//!   `GET .../wifi/settings?name=`: a radio's or an access point's settings;
//!   `GET|POST .../wifi/edit/{setting}`: their dialogs and changes; `POST .../wifi/toggle`:
//!   an access point's switches.
//! - `GET /ui/r/{router}/mesh`: the mesh members; `POST .../mesh/action`: their actions.
//! - Stream `GET /ui/sse/r/{router}/network/traffic?name=`: one interface's traffic.

use axum::{
    Router,
    extract::Query,
    http::{HeaderMap, Uri},
    routing::{get, post},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use crate::{
    WebState, authz::CurrentUser, nav::Section, net_interface_actions, net_interface_detail,
    net_interface_edits, net_interface_traffic, net_interfaces, net_internet, net_internet_address,
    net_internet_create, net_internet_delete, net_internet_edit, net_internet_order,
    net_internet_settings, net_mesh, net_wifi, net_wifi_edit, net_wifi_settings,
    page_kit::gate::Controls, table::rows::TableQuery,
};

/// The routes of the network pages.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/network", get(net_interfaces::page))
        .route(
            "/ui/r/{router}/network/detail",
            get(net_interface_detail::drawer),
        )
        .route(
            "/ui/r/{router}/network/state",
            post(net_interface_actions::state),
        )
        .route(
            "/ui/r/{router}/network/description",
            get(net_interface_edits::description_dialog).post(net_interface_edits::description),
        )
        .route(
            "/ui/r/{router}/network/security-level",
            get(net_interface_edits::security_dialog).post(net_interface_edits::security),
        )
        .merge(internet_routes())
        .merge(wifi_routes())
}

/// The routes of the Wi-Fi and mesh pages.
fn wifi_routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/wifi", get(net_wifi::page))
        .route(
            "/ui/r/{router}/wifi/settings",
            get(net_wifi_settings::settings),
        )
        .route(
            "/ui/r/{router}/wifi/toggle",
            post(net_wifi_settings::toggle),
        )
        .route(
            "/ui/r/{router}/wifi/edit/{setting}",
            get(net_wifi_edit::field_dialog).post(net_wifi_edit::field),
        )
        .route("/ui/r/{router}/mesh", get(net_mesh::page))
        .route("/ui/r/{router}/mesh/action", post(net_mesh::action))
}

/// The routes of the internet connections page.
fn internet_routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/internet", get(net_internet::page))
        .route(
            "/ui/r/{router}/internet/create",
            get(net_internet_create::create_dialog).post(net_internet_create::create),
        )
        .route(
            "/ui/r/{router}/internet/settings",
            get(net_internet_settings::settings),
        )
        .route(
            "/ui/r/{router}/internet/address",
            get(net_internet_address::address_dialog).post(net_internet_address::address),
        )
        .route(
            "/ui/r/{router}/internet/edit/{setting}",
            get(net_internet_edit::field_dialog).post(net_internet_edit::field),
        )
        .route(
            "/ui/r/{router}/internet/default-route",
            post(net_internet_order::default_route),
        )
        .route(
            "/ui/r/{router}/internet/order",
            post(net_internet_order::order),
        )
        .route(
            "/ui/r/{router}/internet/delete",
            get(net_internet_delete::delete_confirmation).post(net_internet_delete::delete),
        )
}

/// The event streams of the network pages, merged outside the request timeout.
pub(crate) fn streams() -> Router<WebState> {
    Router::new().route(
        "/ui/sse/r/{router}/network/traffic",
        get(net_interface_traffic::stream),
    )
}

/// One of the network pages, for their shared tab bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// Interfaces.
    Interfaces,
    /// Internet connections.
    Internet,
    /// Wi-Fi radios, access points and stations.
    Wifi,
    /// Mesh members.
    Mesh,
}

impl Tab {
    /// Every tab, in bar order.
    const ALL: [Self; 4] = [Self::Interfaces, Self::Internet, Self::Wifi, Self::Mesh];

    /// The navigation section the page belongs to.
    pub(crate) const fn section(self) -> Section {
        match self {
            Self::Interfaces | Self::Internet => Section::Network,
            Self::Wifi | Self::Mesh => Section::Wifi,
        }
    }

    /// The page's path segment after the router.
    const fn slug(self) -> &'static str {
        match self {
            Self::Interfaces => "network",
            Self::Internet => "internet",
            Self::Wifi => "wifi",
            Self::Mesh => "mesh",
        }
    }

    /// The tab's label.
    const fn label(self) -> MessageKey {
        match self {
            Self::Interfaces => keys::DOMAINS_INTERFACES,
            Self::Internet => keys::WEB_INTERNET_LABEL,
            Self::Wifi => keys::DOMAINS_WIFI,
            Self::Mesh => keys::WEB_NETWORK_TAB_MESH,
        }
    }
}

/// The tab bar of a network page.
#[derive(Debug, Clone)]
pub(crate) struct Tabs {
    /// Router profile id.
    router: String,
    /// The page shown.
    current: Tab,
}

impl Tabs {
    /// The tab bar of the `current` page of `router`.
    pub(crate) fn new(router: &str, current: Tab) -> Self {
        Self {
            router: router.to_owned(),
            current,
        }
    }

    /// One link per page, the current one marked.
    pub(crate) fn links(&self) -> Vec<TabLink> {
        Tab::ALL
            .into_iter()
            .map(|tab| TabLink {
                href: format!("/ui/r/{}/{}", self.router, tab.slug()),
                label: tab.label(),
                current: tab == self.current,
            })
            .collect()
    }
}

/// One link of the tab bar.
#[derive(Debug, Clone)]
pub(crate) struct TabLink {
    /// The page's address.
    href: String,
    /// The label.
    label: MessageKey,
    /// Whether it is the page shown.
    current: bool,
}

impl TabLink {
    /// The page's address.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// The label.
    pub(crate) const fn label(&self) -> MessageKey {
        self.label
    }

    /// Whether it is the page shown.
    pub(crate) const fn current(&self) -> bool {
        self.current
    }
}

/// One request to a network page: who asks about which router, from which page.
#[derive(Clone, Copy)]
pub(crate) struct Call<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id of the route.
    router: &'call str,
    /// Request headers, for the page the browser shows.
    headers: &'call HeaderMap,
    /// The page whose region a change reads back.
    tab: Tab,
}

impl<'call> Call<'call> {
    /// `user` asks about `router` with `headers`, from the interfaces page.
    pub(crate) const fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
        headers: &'call HeaderMap,
    ) -> Self {
        Self {
            state,
            user,
            router,
            headers,
            tab: Tab::Interfaces,
        }
    }

    /// The same request, from the page of `tab`.
    pub(crate) const fn on(mut self, tab: Tab) -> Self {
        self.tab = tab;
        self
    }

    /// Web services.
    pub(crate) const fn state(self) -> &'call WebState {
        self.state
    }

    /// The signed-in user.
    pub(crate) const fn user(self) -> &'call CurrentUser {
        self.user
    }

    /// Router profile id.
    pub(crate) const fn router(self) -> &'call str {
        self.router
    }

    /// The page whose region a change reads back.
    pub(crate) const fn tab(self) -> Tab {
        self.tab
    }

    /// The table query of the page the browser shows (`HX-Current-URL`), so a table sent
    /// again after a change keeps its filter, order and page.
    pub(crate) fn shown_query(self) -> TableQuery {
        self.headers
            .get("hx-current-url")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Uri>().ok())
            .and_then(|uri| Query::<TableQuery>::try_from_uri(&uri).ok())
            .map_or_else(TableQuery::default, |Query(query)| query)
    }

    /// Who reads the page, with what the role may change there.
    pub(crate) fn viewer(self, controls: Controls) -> Viewer {
        Viewer {
            router: self.router.to_owned(),
            locale: self.user.locale(),
            controls,
        }
    }
}

/// Who reads a network page: the router, the language and what the role may change.
#[derive(Debug, Clone)]
pub(crate) struct Viewer {
    /// Router profile id.
    router: String,
    /// The reader's locale.
    locale: Locale,
    /// What the role may change.
    controls: Controls,
}

impl Viewer {
    /// The parts, for a region that keeps them.
    pub(crate) fn into_parts(self) -> (String, Locale, Controls) {
        (self.router, self.locale, self.controls)
    }
}
