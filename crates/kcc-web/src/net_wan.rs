//! The internet connections as the pages show them: their types, their rows in priority
//! order, and the priority changes that move one of them.

use kcc_domain::{
    DomainError, RouterCtx,
    wan::{self, Connection, ConnectionKind},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    net_change::{scalar, with_prefix},
    table::{
        Direction, Sort,
        rows::{Row, SortKey},
    },
};

/// Every connection of the router of `domain`, highest priority first.
///
/// # Errors
///
/// Returns the router's error.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn links(domain: &RouterCtx) -> Result<Vec<Link>, DomainError> {
    let mut found: Vec<Link> = wan::read_connections(domain)
        .await?
        .into_iter()
        .map(|(id, connection)| Link::new(id, &connection))
        .collect();
    found.sort_by(|left, right| left.key("priority").cmp(&right.key("priority")).reverse());
    Ok(found)
}

/// A connection type the page names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Ethernet IP, by DHCP or a static address.
    Ipoe,
    /// PPP over Ethernet.
    Pppoe,
    /// L2TP tunnel.
    L2tp,
    /// PPTP tunnel.
    Pptp,
}

impl Kind {
    /// Every type, in the order offered.
    pub(crate) const ALL: [Self; 4] = [Self::Ipoe, Self::Pppoe, Self::L2tp, Self::Pptp];

    /// The type of a domain `kind`.
    fn of(kind: ConnectionKind) -> Option<Self> {
        [
            (ConnectionKind::Ipoe, Self::Ipoe),
            (ConnectionKind::Pppoe, Self::Pppoe),
            (ConnectionKind::L2tp, Self::L2tp),
            (ConnectionKind::Pptp, Self::Pptp),
        ]
        .into_iter()
        .find_map(|(domain, page)| (domain == kind).then_some(page))
    }

    /// The type named by `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.slug() == slug)
    }

    /// The form value.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Ipoe => "ipoe",
            Self::Pppoe => "pppoe",
            Self::L2tp => "l2tp",
            Self::Pptp => "pptp",
        }
    }

    /// The label.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Ipoe => keys::WEB_INTERNET_KIND_IPOE,
            Self::Pppoe => keys::WEB_INTERNET_KIND_PPPOE,
            Self::L2tp => keys::WEB_INTERNET_KIND_L2TP,
            Self::Pptp => keys::WEB_INTERNET_KIND_PPTP,
        }
    }

    /// The prefix of the router's interface names of this type; none for IPoE, which runs
    /// on an Ethernet interface.
    pub(crate) const fn prefix(self) -> Option<&'static str> {
        match self {
            Self::Ipoe => None,
            Self::Pppoe => Some("PPPoE"),
            Self::L2tp => Some("L2TP"),
            Self::Pptp => Some("PPTP"),
        }
    }

    /// Whether the connection authenticates with PPP.
    pub(crate) const fn ppp(self) -> bool {
        !matches!(self, Self::Ipoe)
    }
}

/// One connection as the page shows it.
#[derive(Debug, Clone)]
pub(crate) struct Link {
    /// Interface id, such as `PPPoE0`.
    id: String,
    /// Description, when set.
    description: Option<String>,
    /// Connection type.
    kind: Option<Kind>,
    /// Whether the connection is enabled, when reported.
    enabled: Option<bool>,
    /// Address with its prefix length, when set.
    address: Option<String>,
    /// Address as reported, without a prefix length.
    ip: Option<String>,
    /// Netmask as reported.
    mask: Option<String>,
    /// Whether the address comes from DHCP.
    dhcp: bool,
    /// Underlying interface of a tunnel.
    via: Option<String>,
    /// MTU, when reported.
    mtu: Option<u16>,
    /// Whether PPP asks for a default route, when reported.
    default_route: Option<bool>,
    /// Whether an authentication identity is stored.
    identity: bool,
    /// Whether an authentication password is stored.
    password: bool,
    /// Global-routing priority, when reported.
    priority: Option<i64>,
}

impl Link {
    /// The row of `connection`, reported under `id`.
    pub(crate) fn new(id: String, connection: &Connection) -> Self {
        Self {
            id,
            description: scalar(connection.extra.get("description")),
            kind: connection.kind.and_then(Kind::of),
            enabled: connection.state.as_deref().map(|state| state == "up"),
            address: with_prefix(connection.address.as_deref(), connection.extra.get("mask")),
            ip: connection
                .address
                .clone()
                .filter(|address| !address.is_empty()),
            mask: scalar(connection.extra.get("mask")),
            dhcp: connection.dhcp == Some(true),
            via: connection.via.clone(),
            mtu: connection.mtu,
            default_route: connection.default_route,
            identity: connection.identity_present,
            password: connection.password_present,
            priority: connection.priority,
        }
    }

    /// Interface id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Connection type.
    pub(crate) const fn kind(&self) -> Option<Kind> {
        self.kind
    }

    /// Global-routing priority.
    pub(crate) const fn priority(&self) -> Option<i64> {
        self.priority
    }

    /// The type in `locale`.
    pub(crate) fn kind_text(&self, locale: Locale) -> Option<String> {
        self.kind.map(|kind| tr(locale, kind.label(), None))
    }

    /// The state in `locale`.
    pub(crate) fn state_text(&self, locale: Locale) -> Option<String> {
        self.enabled.map(|enabled| {
            let key = if enabled {
                keys::COMMON_ENABLED
            } else {
                keys::COMMON_DISABLED
            };
            tr(locale, key, None)
        })
    }

    /// The address in `locale`: the address, or "Automatic (DHCP)" while DHCP is on and
    /// no address is known yet.
    pub(crate) fn address_text(&self, locale: Locale) -> Option<String> {
        self.address.clone().or_else(|| {
            self.dhcp
                .then(|| tr(locale, keys::WEB_INTERNET_MODE_DHCP, None))
        })
    }

    /// Address as reported, without a prefix length.
    pub(crate) fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    /// Netmask as reported.
    pub(crate) fn mask(&self) -> Option<&str> {
        self.mask.as_deref()
    }

    /// Whether the address comes from DHCP.
    pub(crate) const fn dhcp(&self) -> bool {
        self.dhcp
    }

    /// Underlying interface of a tunnel.
    pub(crate) fn via(&self) -> Option<&str> {
        self.via.as_deref()
    }

    /// MTU as text.
    pub(crate) fn mtu_text(&self) -> Option<String> {
        self.mtu.map(|mtu| mtu.to_string())
    }

    /// Whether PPP asks for a default route.
    pub(crate) const fn default_route(&self) -> Option<bool> {
        self.default_route
    }

    /// Whether `secret` (the identity, else the password) is stored, in `locale`.
    pub(crate) fn presence_text(&self, locale: Locale, identity: bool) -> String {
        let stored = if identity {
            self.identity
        } else {
            self.password
        };
        let key = if stored {
            keys::WEB_INTERNET_SET
        } else {
            keys::WEB_INTERNET_NOT_SET
        };
        tr(locale, key, None)
    }

    /// Description, when set.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl Row for Link {
    const COLUMNS: &'static [&'static str] = &["priority", "name", "type", "state"];
    const DEFAULT: Sort = Sort::new("priority", Direction::Descending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "priority" => self
                .priority
                .map_or(SortKey::Missing, |value| SortKey::Number(i128::from(value))),
            "type" => self
                .kind
                .map_or(SortKey::Missing, |kind| SortKey::text(kind.slug())),
            "state" => self.enabled.map_or(SortKey::Missing, |enabled| {
                SortKey::Number(i128::from(enabled))
            }),
            _ => SortKey::text(&self.id),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.id.as_str()),
            self.description.as_deref(),
            self.address.as_deref(),
            self.via.as_deref(),
            self.kind.map(Kind::slug),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}
