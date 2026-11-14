//! The frame of the DNS and VPN pages: the tabs, the page around a tab's region, and the
//! answer to a change, which is its outcome with the region read back.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{cells::Act, region::Region};
use crate::{
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        outcome::{Outcome, with_status},
        respond,
    },
};

/// One tab of the DNS and VPN pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// The DNS servers the router asks: over TLS, over HTTPS, plain.
    Servers,
    /// Content filtering: the engine, interception, profiles and assignments.
    Filtering,
    /// Static DNS records.
    Records,
    /// Domain lists.
    Lists,
    /// Routes chosen by domain list.
    Routes,
    /// VPN client connections.
    Connections,
    /// VPN servers.
    VpnServers,
}

impl Tab {
    /// The DNS tabs, in order.
    const DNS: [Self; 5] = [
        Self::Servers,
        Self::Filtering,
        Self::Records,
        Self::Lists,
        Self::Routes,
    ];

    /// The VPN tabs, in order.
    const VPN: [Self; 2] = [Self::Connections, Self::VpnServers];

    /// The DNS tab named by the route segment `slug`.
    pub(crate) fn dns(slug: &str) -> Option<Self> {
        Self::DNS
            .into_iter()
            .find(|tab| !tab.slug().is_empty() && tab.slug() == slug)
    }

    /// The route segment after the section; empty for the section's first tab.
    const fn slug(self) -> &'static str {
        match self {
            Self::Servers | Self::Connections => "",
            Self::Filtering => "filtering",
            Self::Records => "records",
            Self::Lists => "lists",
            Self::Routes => "routes",
            Self::VpnServers => "servers",
        }
    }

    /// The navigation section.
    pub(crate) const fn section(self) -> Section {
        match self {
            Self::Servers | Self::Filtering | Self::Records | Self::Lists | Self::Routes => {
                Section::Dns
            }
            Self::Connections | Self::VpnServers => Section::Vpn,
        }
    }

    /// The tab's page on `router`.
    pub(crate) fn href(self, router: &str) -> String {
        let section = self.section().slug();
        match self.slug() {
            "" => format!("/ui/r/{router}/{section}"),
            slug => format!("/ui/r/{router}/{section}/{slug}"),
        }
    }

    /// The tab's label, also its page title.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Servers => keys::WEB_DNS_TAB_SERVERS,
            Self::Filtering => keys::WEB_DNS_TAB_FILTERING,
            Self::Records => keys::WEB_DNS_TAB_RECORDS,
            Self::Lists => keys::WEB_DNS_TAB_LISTS,
            Self::Routes => keys::WEB_DNS_TAB_ROUTES,
            Self::Connections => keys::WEB_VPN_TAB_CONNECTIONS,
            Self::VpnServers => keys::WEB_VPN_TAB_SERVERS,
        }
    }

    /// The tabs of the same section.
    const fn siblings(self) -> &'static [Self] {
        match self {
            Self::Servers | Self::Filtering | Self::Records | Self::Lists | Self::Routes => {
                &Self::DNS
            }
            Self::Connections | Self::VpnServers => &Self::VPN,
        }
    }
}

/// One link of the tab bar.
#[derive(Debug)]
struct TabLink {
    /// The tab's page.
    href: String,
    /// The tab's label.
    label: MessageKey,
    /// Whether the page belongs to the tab.
    current: bool,
}

/// A DNS or VPN page: the tab bar, the title with the page's actions, the outcome region
/// and the tab's region.
#[derive(Template)]
#[template(path = "pages/dns_vpn.html")]
pub(crate) struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The tab the page belongs to.
    tab: Tab,
    /// The localized title.
    title: String,
    /// The page's actions, the primary first.
    actions: Vec<Act>,
    /// A link back to the tab, for a page below it.
    back: Option<Act>,
    /// The tab's region.
    region: Region,
}

localized!(Page);

impl Page {
    /// The page of `tab` on `router`, showing `region`, titled with the tab's label.
    pub(crate) fn new(shell: Shell, (router, tab): (String, Tab), region: Region) -> Self {
        let title = tr(shell.locale(), tab.label(), None);
        Self {
            shell,
            router,
            tab,
            title,
            actions: Vec::new(),
            back: None,
            region,
        }
    }

    /// Titles the page `title`.
    pub(crate) fn titled(mut self, title: String) -> Self {
        self.title = title;
        self
    }

    /// Shows `actions` beside the title.
    pub(crate) fn with_actions(mut self, actions: Vec<Act>) -> Self {
        self.actions = actions;
        self
    }

    /// Shows `back` above the title.
    pub(crate) fn with_back(mut self, back: Act) -> Self {
        self.back = Some(back);
        self
    }

    /// The links of the tab bar.
    fn tabs(&self) -> Vec<TabLink> {
        self.tab
            .siblings()
            .iter()
            .map(|tab| TabLink {
                href: tab.href(&self.router),
                label: tab.label(),
                current: *tab == self.tab,
            })
            .collect()
    }

    /// The tab bar's accessible name: the section.
    const fn section_label(&self) -> MessageKey {
        self.tab.section().label()
    }
}

/// The answer to a change: its outcome, notes on what it left out, and the region read
/// back out of band.
#[derive(Template)]
#[template(path = "partials/dns_vpn_result.html")]
pub(crate) struct Answered {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
    /// Localized notes shown with a success: what the change could not include.
    notes: Vec<String>,
    /// The region read back, sent out of band.
    refreshed: Option<Region>,
    /// The page actions read back, sent out of band with the region.
    actions: Vec<Act>,
}

localized!(Answered);

impl Answered {
    /// The answer showing `outcome` in `locale`.
    pub(crate) const fn new(outcome: Outcome, locale: Locale) -> Self {
        Self {
            shell: fragment_shell(locale),
            outcome,
            notes: Vec::new(),
            refreshed: None,
            actions: Vec::new(),
        }
    }

    /// Sends the region and the page actions, read back, out of band.
    pub(crate) fn refreshed(mut self, read_back: Option<(Region, Vec<Act>)>) -> Self {
        if let Some((region, actions)) = read_back {
            self.refreshed = Some(region.out_of_band());
            self.actions = actions;
        }
        self
    }

    /// Shows `notes` with the outcome.
    pub(crate) fn notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    /// The response: the outcome's status, the shared dialog closed.
    pub(crate) fn respond(self) -> Response {
        let status = self.outcome.status();
        respond::close_dialog(with_status(errors::render(&self), status))
    }
}
