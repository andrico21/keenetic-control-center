//! One row of the clients table: a client as the router reports it, its state, connection
//! and counters formatted in the page locale, and how the table sorts and filters it.

use core::{net::Ipv4Addr, str::FromStr as _};

use fluent_bundle::FluentArgs;
use kcc_domain::clients::Client;
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};
use serde_json::Value;

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// Whether a client is connected now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    /// Connected.
    Online,
    /// Remembered, not connected.
    Offline,
}

/// How a client is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Medium {
    /// A cable through a bridge port.
    Wired,
    /// An access point.
    Wireless,
}

/// One client as the table shows it.
#[derive(Debug, Clone)]
pub(crate) struct ClientRow {
    /// MAC address, the row's identity.
    mac: String,
    /// Registered or reported name.
    name: Option<String>,
    /// Current IP address.
    ip: Option<String>,
    /// Serving bridge or access point.
    interface: Option<String>,
    /// Connected now or not.
    presence: Presence,
    /// Cable or Wi-Fi.
    medium: Medium,
    /// Signal strength in dBm.
    rssi: Option<i16>,
    /// Signal strength, localized.
    signal: Option<String>,
    /// Bytes received and sent, when both are reported.
    traffic: Option<(u64, u64)>,
    /// Bytes received and sent, localized.
    traffic_text: Option<String>,
    /// Connection policy.
    policy: Option<String>,
    /// Schedule.
    schedule: Option<String>,
    /// Whether access is denied.
    blocked: bool,
    /// Whether the router remembers the client as a known host.
    registered: bool,
}

impl ClientRow {
    /// The row of `client` in `locale`; `None` for a client without a MAC address.
    pub(crate) fn new(client: Client, locale: Locale) -> Option<Self> {
        let online = client.link.as_deref() == Some("up")
            || client.extra.get("active").and_then(Value::as_bool) == Some(true);
        let wireless = client.rssi.is_some()
            || client.extra.contains_key("ssid")
            || client
                .interface
                .as_deref()
                .is_some_and(|name| name.contains("AccessPoint") || name.starts_with("WifiMaster"));
        let traffic = client.rx.zip(client.tx);
        Some(Self {
            signal: client.rssi.map(|rssi| {
                let mut args = FluentArgs::new();
                args.set("value", rssi.to_string());
                tr(locale, keys::WEB_CLIENTS_SIGNAL_VALUE, Some(&args))
            }),
            traffic_text: traffic.map(|(rx, tx)| {
                let mut args = FluentArgs::new();
                args.set("first", format::bytes(locale, rx));
                args.set("last", format::bytes(locale, tx));
                tr(locale, keys::WEB_CLIENTS_TRAFFIC_VALUE, Some(&args))
            }),
            mac: client.mac.filter(|mac| !mac.is_empty())?,
            name: client.name.filter(|name| !name.is_empty()),
            ip: client.ip,
            interface: client.interface,
            presence: if online {
                Presence::Online
            } else {
                Presence::Offline
            },
            medium: if wireless {
                Medium::Wireless
            } else {
                Medium::Wired
            },
            rssi: client.rssi,
            traffic,
            policy: client.policy.filter(|policy| !policy.is_empty()),
            schedule: client.schedule.filter(|schedule| !schedule.is_empty()),
            blocked: client.access.as_deref() == Some("deny"),
            registered: client.registered == Some(true),
        })
    }

    /// MAC address.
    pub(crate) fn mac(&self) -> &str {
        &self.mac
    }

    /// Registered or reported name.
    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Current IP address.
    pub(crate) fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    /// Serving bridge or access point.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Connected now or not.
    pub(crate) const fn presence(&self) -> Presence {
        self.presence
    }

    /// Cable or Wi-Fi.
    pub(crate) const fn medium(&self) -> Medium {
        self.medium
    }

    /// Whether the client is connected now.
    pub(crate) fn online(&self) -> bool {
        self.presence == Presence::Online
    }

    /// Signal strength, localized; `None` for a wired client.
    pub(crate) fn signal(&self) -> Option<&str> {
        self.signal.as_deref()
    }

    /// Bytes received and sent, localized.
    pub(crate) fn traffic(&self) -> Option<&str> {
        self.traffic_text.as_deref()
    }

    /// Connection policy.
    pub(crate) fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    /// Schedule.
    pub(crate) fn schedule(&self) -> Option<&str> {
        self.schedule.as_deref()
    }

    /// Whether access is denied.
    pub(crate) const fn blocked(&self) -> bool {
        self.blocked
    }

    /// Whether the router remembers the client as a known host.
    pub(crate) const fn registered(&self) -> bool {
        self.registered
    }
}

impl Row for ClientRow {
    const COLUMNS: &'static [&'static str] = &[
        "name",
        "mac",
        "ip",
        "interface",
        "signal",
        "traffic",
        "policy",
        "access",
        "schedule",
    ];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        let text = |value: Option<&str>| value.map_or(SortKey::Missing, SortKey::text);
        match column {
            "mac" => SortKey::text(&self.mac),
            "ip" => self.ip.as_deref().map_or(SortKey::Missing, |ip| {
                Ipv4Addr::from_str(ip).map_or_else(
                    |_| SortKey::text(ip),
                    |address| SortKey::Number(u32::from(address).into()),
                )
            }),
            "interface" => text(self.interface.as_deref()),
            "signal" => self
                .rssi
                .map_or(SortKey::Missing, |rssi| SortKey::Number(rssi.into())),
            "traffic" => self.traffic.map_or(SortKey::Missing, |(rx, tx)| {
                SortKey::Number(rx.saturating_add(tx).into())
            }),
            "policy" => text(self.policy.as_deref()),
            "access" => SortKey::Number(i128::from(u8::from(self.blocked))),
            "schedule" => text(self.schedule.as_deref()),
            _ => text(self.name.as_deref()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.mac.as_str()),
            self.name.as_deref(),
            self.ip.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}
