//! The Web UI sections and their routes under `/ui`.

use kcc_i18n::{bundle::MessageKey, keys};

/// One top-level section of the Web UI navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Section {
    /// Fleet and router overview, the landing page at `/ui/`.
    Dashboard,
    /// Connected and registered clients.
    Clients,
    /// Interfaces, WAN and LAN.
    Network,
    /// Wireless networks and radios.
    Wifi,
    /// Static routes and routing policy.
    Routing,
    /// Firewall rules and port forwarding.
    Firewall,
    /// DNS servers and filters.
    Dns,
    /// VPN servers and tunnels.
    Vpn,
    /// System status, firmware and components.
    System,
    /// Configuration files, backups and pending changes.
    Configuration,
    /// Raw RCI and CLI access.
    Advanced,
    /// Configuration migration between routers.
    Migration,
    /// Settings presets and copying settings between routers.
    Presets,
    /// Accounts, roles and audit log.
    Admin,
}

impl Section {
    /// Every section, in navigation order.
    pub const ALL: [Self; 14] = [
        Self::Dashboard,
        Self::Clients,
        Self::Network,
        Self::Wifi,
        Self::Routing,
        Self::Firewall,
        Self::Dns,
        Self::Vpn,
        Self::System,
        Self::Configuration,
        Self::Advanced,
        Self::Migration,
        Self::Presets,
        Self::Admin,
    ];

    /// The path segment after `/ui/`; empty for the dashboard.
    #[inline]
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Dashboard => "",
            Self::Clients => "clients",
            Self::Network => "network",
            Self::Wifi => "wifi",
            Self::Routing => "routing",
            Self::Firewall => "firewall",
            Self::Dns => "dns",
            Self::Vpn => "vpn",
            Self::System => "system",
            Self::Configuration => "configuration",
            Self::Advanced => "advanced",
            Self::Migration => "migrate",
            Self::Presets => "presets",
            Self::Admin => "admin",
        }
    }

    /// The section's URL.
    #[inline]
    #[must_use]
    pub const fn href(self) -> &'static str {
        match self {
            Self::Dashboard => "/ui/",
            Self::Clients => "/ui/clients",
            Self::Network => "/ui/network",
            Self::Wifi => "/ui/wifi",
            Self::Routing => "/ui/routing",
            Self::Firewall => "/ui/firewall",
            Self::Dns => "/ui/dns",
            Self::Vpn => "/ui/vpn",
            Self::System => "/ui/system",
            Self::Configuration => "/ui/configuration",
            Self::Advanced => "/ui/advanced",
            Self::Migration => "/ui/migrate",
            Self::Presets => "/ui/presets",
            Self::Admin => "/ui/admin",
        }
    }

    /// The section's page on one router, the path after `/ui/r/{router}/`; `None` for the
    /// sections that are not about one router.
    #[inline]
    #[must_use]
    pub const fn router_page(self) -> Option<&'static str> {
        match self {
            Self::Clients => Some("clients"),
            Self::Network => Some("network"),
            Self::Wifi => Some("wifi"),
            Self::Routing => Some("routing"),
            Self::Firewall => Some("firewall"),
            Self::Dns => Some("dns"),
            Self::Vpn => Some("vpn"),
            Self::System => Some("system/general"),
            Self::Dashboard
            | Self::Configuration
            | Self::Advanced
            | Self::Migration
            | Self::Presets
            | Self::Admin => None,
        }
    }

    /// The navigation link of the section on a page about `router`: the section's page on
    /// that router, or [`href`](Self::href) without a router or for a section that is not
    /// about one router.
    #[inline]
    #[must_use]
    pub fn href_on(self, router: Option<&str>) -> String {
        match (self.router_page(), router) {
            (Some(page), Some(id)) => format!("/ui/r/{id}/{page}"),
            (Some(_) | None, _) => self.href().to_owned(),
        }
    }

    /// The navigation label, also the page title.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        match self {
            Self::Dashboard => keys::WEB_NAV_DASHBOARD,
            Self::Clients => keys::WEB_NAV_CLIENTS,
            Self::Network => keys::WEB_NAV_NETWORK,
            Self::Wifi => keys::WEB_NAV_WIFI,
            Self::Routing => keys::WEB_NAV_ROUTING,
            Self::Firewall => keys::WEB_NAV_FIREWALL,
            Self::Dns => keys::WEB_NAV_DNS,
            Self::Vpn => keys::WEB_NAV_VPN,
            Self::System => keys::WEB_NAV_SYSTEM,
            Self::Configuration => keys::WEB_NAV_CONFIGURATION,
            Self::Advanced => keys::WEB_NAV_ADVANCED,
            Self::Migration => keys::WEB_NAV_MIGRATION,
            Self::Presets => keys::WEB_NAV_PRESETS,
            Self::Admin => keys::WEB_NAV_ADMIN,
        }
    }

    /// The section whose [`slug`](Self::slug) is `slug`.
    #[inline]
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.slug() == slug)
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::Section;

    #[test]
    fn slugs_round_trip_and_hrefs_match() {
        for section in Section::ALL {
            assert_eq!(
                Section::from_slug(section.slug()),
                Some(section),
                "{}",
                section.href()
            );
            assert_eq!(
                section.href(),
                format!("/ui/{}", section.slug()),
                "{}",
                section.slug()
            );
        }
        assert_eq!(Section::from_slug("dashboard"), None, "dashboard is /ui/");
        assert_eq!(Section::from_slug("Clients"), None, "slugs are exact");
    }
}
