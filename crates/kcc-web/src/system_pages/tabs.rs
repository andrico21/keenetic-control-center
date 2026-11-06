//! The tab bar every system page shows: one link per system page of the router, the
//! current one marked.

use kcc_i18n::{bundle::MessageKey, keys};

/// One system page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// Identity, time, restart and factory reset.
    General,
    /// Router accounts and their service tags.
    Users,
    /// Router services.
    Services,
    /// Firmware components and updates.
    Components,
    /// Media and USB devices.
    Storage,
    /// Schedules and their timed actions.
    Schedules,
    /// The KeenDNS name and remote access.
    KeenDns,
    /// The router log.
    Logs,
    /// Network diagnostics.
    Diagnostics,
}

impl Tab {
    /// Every system page, in tab order.
    const ALL: [Self; 9] = [
        Self::General,
        Self::Users,
        Self::Services,
        Self::Components,
        Self::Storage,
        Self::Schedules,
        Self::KeenDns,
        Self::Logs,
        Self::Diagnostics,
    ];

    /// The path segment after `/system/`.
    const fn slug(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Users => "users",
            Self::Services => "services",
            Self::Components => "components",
            Self::Storage => "storage",
            Self::Schedules => "schedules",
            Self::KeenDns => "keendns",
            Self::Logs => "logs",
            Self::Diagnostics => "diagnostics",
        }
    }

    /// The tab label, also the page title.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::General => keys::WEB_SYSTEM_GENERAL_TITLE,
            Self::Users => keys::WEB_SYSTEM_USERS_TITLE,
            Self::Services => keys::WEB_SYSTEM_SERVICES_TITLE,
            Self::Components => keys::WEB_SYSTEM_COMPONENTS_TITLE,
            Self::Storage => keys::WEB_SYSTEM_STORAGE_TITLE,
            Self::Schedules => keys::WEB_SYSTEM_SCHEDULES_TITLE,
            Self::KeenDns => keys::WEB_SYSTEM_KEENDNS_TITLE,
            Self::Logs => keys::WEB_SYSTEM_LOGS_TITLE,
            Self::Diagnostics => keys::WEB_SYSTEM_DIAGNOSTICS_TITLE,
        }
    }
}

/// The tab bar of one system page (`partials/system_tabs.html`).
#[derive(Debug, Clone)]
pub(crate) struct TabBar {
    /// Router profile id.
    router: String,
    /// The page shown.
    current: Tab,
}

/// One link of the tab bar.
#[derive(Debug, Clone)]
pub(crate) struct TabLink {
    /// The page's URL.
    href: String,
    /// The page's label.
    label: MessageKey,
    /// Whether it is the page shown.
    current: bool,
}

impl TabBar {
    /// The tab bar of the page `current` on `router`.
    pub(crate) const fn new(router: String, current: Tab) -> Self {
        Self { router, current }
    }

    /// The links, in tab order.
    pub(crate) fn links(&self) -> Vec<TabLink> {
        Tab::ALL
            .into_iter()
            .map(|tab| TabLink {
                href: format!("/ui/r/{}/system/{}", self.router, tab.slug()),
                label: tab.label(),
                current: tab == self.current,
            })
            .collect()
    }

    /// The label of the page shown, its title.
    pub(crate) const fn title(&self) -> MessageKey {
        self.current.label()
    }
}

impl TabLink {
    /// The page's URL.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// The page's label.
    pub(crate) const fn label(&self) -> MessageKey {
        self.label
    }

    /// Whether it is the page shown.
    pub(crate) const fn current(&self) -> bool {
        self.current
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{Tab, TabBar, TabLink};

    #[test]
    fn every_system_page_has_one_tab_and_the_current_one_is_marked() {
        let links = TabBar::new("home".to_owned(), Tab::Services).links();
        assert_eq!(links.len(), Tab::ALL.len(), "one tab per page");
        let current: Vec<&str> = links
            .iter()
            .filter(|link| link.current())
            .map(TabLink::href)
            .collect();
        assert_eq!(current, ["/ui/r/home/system/services"], "the page shown");
        assert_eq!(
            links.first().map(TabLink::href),
            Some("/ui/r/home/system/general"),
            "general first"
        );
    }
}
