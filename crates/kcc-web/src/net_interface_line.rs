//! One interface as the pages show it: its row of the interfaces table, and the security
//! levels the page offers.

use kcc_domain::interfaces::{Interface, SecurityLevel};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    net_change::with_prefix,
    table::{
        Direction, Sort,
        rows::{Row, SortKey},
    },
};

/// An interface's security zone, as the page offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    /// Facing the internet.
    Public,
    /// The home network.
    Private,
    /// An isolated local network.
    Protected,
}

impl Level {
    /// Every level, in the order offered.
    pub(crate) const ALL: [Self; 3] = [Self::Private, Self::Public, Self::Protected];

    /// The level named by the router keyword `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.slug() == slug)
    }

    /// The router keyword.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Protected => "protected",
        }
    }

    /// The label.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Public => keys::WEB_NETWORK_SECURITY_PUBLIC,
            Self::Private => keys::WEB_NETWORK_SECURITY_PRIVATE,
            Self::Protected => keys::WEB_NETWORK_SECURITY_PROTECTED,
        }
    }

    /// The interfaces domain's level.
    pub(crate) const fn domain(self) -> SecurityLevel {
        match self {
            Self::Public => SecurityLevel::Public,
            Self::Private => SecurityLevel::Private,
            Self::Protected => SecurityLevel::Protected,
        }
    }
}

/// One interface as the table shows it.
#[derive(Debug, Clone)]
pub(crate) struct Line {
    /// Interface id, such as `Bridge0`.
    id: String,
    /// Description, when set.
    description: Option<String>,
    /// Router interface type, such as `Bridge`.
    kind: Option<String>,
    /// Whether the link is up, when reported.
    link: Option<bool>,
    /// Whether the interface is enabled, when reported.
    enabled: Option<bool>,
    /// IPv4 address with its prefix length, when set.
    address: Option<String>,
    /// Security level, when reported.
    level: Option<Level>,
}

impl Line {
    /// The line of `interface`, reported under `id`.
    pub(crate) fn new(id: String, interface: &Interface) -> Self {
        Self {
            id,
            description: interface
                .description
                .clone()
                .filter(|text| !text.is_empty()),
            kind: interface.kind.clone(),
            link: interface.link.as_deref().map(|link| link == "up"),
            enabled: interface.state.as_deref().map(|state| state == "up"),
            address: with_prefix(interface.address.as_deref(), interface.extra.get("mask")),
            level: interface
                .security_level
                .as_deref()
                .and_then(Level::from_slug),
        }
    }

    /// Interface id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Description, when set.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Security level, when reported.
    pub(crate) const fn level(&self) -> Option<Level> {
        self.level
    }

    /// Whether the interface carries an IPv4 address or a security level, the interfaces
    /// a security level applies to.
    pub(crate) const fn routed(&self) -> bool {
        self.address.is_some() || self.level.is_some()
    }

    /// The link label.
    const fn link_label(&self) -> Option<MessageKey> {
        match self.link {
            Some(true) => Some(keys::DOMAINS_INTERFACE_UP),
            Some(false) => Some(keys::DOMAINS_INTERFACE_DOWN),
            None => None,
        }
    }

    /// The status-pill value of the link.
    pub(crate) const fn link_value(&self) -> &'static str {
        match self.link {
            Some(true) => "online",
            Some(false) | None => "unknown",
        }
    }

    /// The state label.
    const fn state_label(&self) -> Option<MessageKey> {
        match self.enabled {
            Some(true) => Some(keys::COMMON_ENABLED),
            Some(false) => Some(keys::COMMON_DISABLED),
            None => None,
        }
    }

    /// The link in `locale`: up or down.
    pub(crate) fn link_text(&self, locale: Locale) -> Option<String> {
        self.link_label().map(|key| tr(locale, key, None))
    }

    /// The state in `locale`: enabled or disabled.
    pub(crate) fn state_text(&self, locale: Locale) -> Option<String> {
        self.state_label().map(|key| tr(locale, key, None))
    }

    /// The security level in `locale`.
    pub(crate) fn level_text(&self, locale: Locale) -> Option<String> {
        self.level.map(|level| tr(locale, level.label(), None))
    }

    /// Router interface type.
    pub(crate) fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Address with its prefix length.
    pub(crate) fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Whether the interface is enabled, when reported.
    pub(crate) const fn enabled(&self) -> Option<bool> {
        self.enabled
    }
}

impl Row for Line {
    const COLUMNS: &'static [&'static str] =
        &["name", "type", "link", "state", "address", "security"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        let text = |value: Option<&str>| value.map_or(SortKey::Missing, SortKey::text);
        let flag = |value: Option<bool>| {
            value.map_or(SortKey::Missing, |up| SortKey::Number(i128::from(up)))
        };
        match column {
            "type" => text(self.kind.as_deref()),
            "link" => flag(self.link),
            "state" => flag(self.enabled),
            "address" => text(self.address.as_deref()),
            "security" => text(self.level.map(Level::slug)),
            _ => SortKey::text(&self.id),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.id.as_str()),
            self.description.as_deref(),
            self.kind.as_deref(),
            self.address.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}
