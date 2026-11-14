//! The local network pages of one router: its clients, its DHCP service and its network
//! segments, built on the domain page kit (`DESIGN.md`, "Domain page kit").
//!
//! Routes (route table: `Read` and the router scope; every change opens its operation
//! through the kit, which re-checks the operation's permissions and audits the change):
//!
//! - `GET /ui/clients`: every router the user may read, with its local network pages.
//! - `GET /ui/r/{router}/clients`: connected and remembered clients, filtered by state,
//!   connection and text, sorted and paged; `GET|POST .../clients/{action}?mac=` runs a
//!   row action (`name`, `access`, `policy`, `schedule`, `priority`, `wake`, `remove`).
//! - `GET /ui/r/{router}/dhcp` (pools) and `.../dhcp/{leases|bindings|arp}`;
//!   `GET|POST .../dhcp/pools/edit[?name=]` adds or changes a pool and
//!   `GET|POST .../dhcp/leases/new` adds a static lease.
//! - `GET /ui/r/{router}/segments`: the segments kcc created; `GET|POST .../segments/new`,
//!   `POST .../segments/review` and `POST .../segments/create` are the creation wizard, and
//!   `GET|POST .../segments/delete?id=` the typed-name delete.

mod client_act;
mod client_actions;
mod client_rows;
mod client_table;
mod client_view;
mod clients;
mod dhcp;
mod dhcp_forms;
mod dhcp_lease;
mod dhcp_page;
mod dhcp_rows;
mod dhcp_table;
mod landing;
mod segment_create;
mod segment_delete;
mod segment_form;
mod segment_known;
mod segment_list;
mod segment_review;
mod segments;

use askama::Template;
use axum::{
    Router,
    response::Response,
    routing::{get, post},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use crate::{
    WebState,
    page_kit::{outcome::Outcome, request::rendered, respond::changed},
};

/// The local network routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/clients", get(landing::page))
        .route("/ui/r/{router}/clients", get(clients::page))
        .route(
            "/ui/r/{router}/clients/{action}",
            get(client_actions::dialog).post(client_actions::act),
        )
        .route("/ui/r/{router}/dhcp", get(dhcp_page::pools))
        .route("/ui/r/{router}/dhcp/{view}", get(dhcp_page::view))
        .route(
            "/ui/r/{router}/dhcp/pools/edit",
            get(dhcp_forms::pool_dialog).post(dhcp_forms::save_pool),
        )
        .route(
            "/ui/r/{router}/dhcp/leases/new",
            get(dhcp_lease::lease_dialog).post(dhcp_lease::add_lease),
        )
        .route("/ui/r/{router}/segments", get(segments::page))
        .route(
            "/ui/r/{router}/segments/new",
            get(segments::details).post(segments::back),
        )
        .route("/ui/r/{router}/segments/review", post(segments::review))
        .route(
            "/ui/r/{router}/segments/create",
            post(segment_create::create),
        )
        .route(
            "/ui/r/{router}/segments/delete",
            get(segment_delete::dialog).post(segment_delete::delete),
        )
}

/// One page of the local network family, for the tabs above each page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// The clients table.
    Clients,
    /// The DHCP views.
    Dhcp,
    /// The segments.
    Segments,
}

impl Tab {
    /// Every tab, in order.
    const ALL: [Self; 3] = [Self::Clients, Self::Dhcp, Self::Segments];

    /// The tab's page on `router`.
    fn href(self, router: &str) -> String {
        match self {
            Self::Clients => format!("/ui/r/{router}/clients"),
            Self::Dhcp => format!("/ui/r/{router}/dhcp"),
            Self::Segments => format!("/ui/r/{router}/segments"),
        }
    }

    /// The tab's label, also its page title.
    const fn label(self) -> MessageKey {
        match self {
            Self::Clients => keys::WEB_CLIENTS_TITLE,
            Self::Dhcp => keys::WEB_DHCP_TITLE,
            Self::Segments => keys::WEB_SEGMENTS_TITLE,
        }
    }

    /// The links of the family's tabs on `router`, `self` marked current.
    pub(crate) fn links(self, router: &str) -> Vec<TabLink> {
        Self::ALL
            .into_iter()
            .map(|tab| TabLink::new(tab.href(router), tab.label(), tab == self))
            .collect()
    }
}

/// One link of the family's tabs (`partials/lan_tabs.html`).
#[derive(Debug, Clone)]
pub(crate) struct TabLink {
    /// The page.
    href: String,
    /// Its label.
    label: MessageKey,
    /// Whether it is the page shown.
    current: bool,
}

impl TabLink {
    /// A link to `href` labelled `label`, marked current when `current`.
    pub(crate) const fn new(href: String, label: MessageKey, current: bool) -> Self {
        Self {
            href,
            label,
            current,
        }
    }

    /// The page.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// Its label.
    pub(crate) const fn label(&self) -> MessageKey {
        self.label
    }

    /// Whether it is the page shown.
    pub(crate) const fn current(&self) -> bool {
        self.current
    }
}

/// A sentence about a change beyond its outcome, such as the failed segment step.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<p class=\"notice\" data-tone=\"error\">{{ text }}</p>"
)]
struct Note<'text> {
    /// The sentence.
    text: &'text str,
}

/// The answer to a change: `outcome` with `refreshed` out of band and `note` beside it,
/// the dialog closed.
pub(crate) fn answer(
    outcome: Outcome,
    refreshed: Option<String>,
    note: Option<String>,
    locale: Locale,
) -> Response {
    let extra = note.and_then(|text| rendered(&Note { text: &text }));
    changed(outcome, refreshed, extra, locale)
}
