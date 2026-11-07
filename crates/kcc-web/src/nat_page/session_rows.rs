//! One active connection of the router's NAT table, as the connections view shows and
//! sorts it.

use core::net::Ipv4Addr;

use kcc_domain::nat::model::NatSession;
use serde_json::Value;

use crate::{
    net_change::scalar,
    table::{
        Direction, Sort,
        rows::{Row, SortKey},
    },
};

/// One active connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {
    /// Protocol.
    protocol: Option<String>,
    /// Source address and port.
    source: Option<String>,
    /// Destination address and port.
    destination: Option<String>,
    /// Translated address and port.
    translated: Option<String>,
    /// Interface.
    interface: Option<String>,
    /// Connection state.
    state: Option<String>,
    /// Bytes received.
    received: Option<u64>,
    /// Bytes sent.
    sent: Option<u64>,
}

impl Session {
    /// The connection of one `show ip nat` row.
    pub(crate) fn from_row(row: &NatSession) -> Self {
        let field = |name: &str| scalar(row.fields.get(name));
        let endpoint = |address: &str, port: &str| {
            let host = field(address)?;
            Some(field(port).map_or_else(|| host.clone(), |number| format!("{host}:{number}")))
        };
        Self {
            protocol: field("protocol"),
            source: endpoint("source", "source-port"),
            destination: endpoint("destination", "destination-port"),
            translated: endpoint("translated-address", "translated-port"),
            interface: field("interface"),
            state: field("state"),
            received: row.fields.get("rxbytes").and_then(Value::as_u64),
            sent: row.fields.get("txbytes").and_then(Value::as_u64),
        }
    }

    /// Protocol.
    pub(crate) fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Source address and port.
    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Destination address and port.
    pub(crate) fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    /// Translated address and port.
    pub(crate) fn translated(&self) -> Option<&str> {
        self.translated.as_deref()
    }

    /// Interface.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Connection state.
    pub(crate) fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Bytes received.
    pub(crate) const fn received(&self) -> Option<u64> {
        self.received
    }

    /// Bytes sent.
    pub(crate) const fn sent(&self) -> Option<u64> {
        self.sent
    }

    /// The texts a filter looks in.
    fn texts(&self) -> [Option<&str>; 6] {
        [
            self.protocol(),
            self.source(),
            self.destination(),
            self.translated(),
            self.interface(),
            self.state(),
        ]
    }
}

impl Row for Session {
    const COLUMNS: &'static [&'static str] = &[
        "protocol",
        "source",
        "destination",
        "translated",
        "interface",
        "state",
        "received",
        "sent",
    ];

    const DEFAULT: Sort = Sort::new("source", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        let text = |value: Option<&str>| value.map_or(SortKey::Missing, SortKey::text);
        let number =
            |value: Option<u64>| value.map_or(SortKey::Missing, |n| SortKey::Number(i128::from(n)));
        match column {
            "protocol" => text(self.protocol()),
            "destination" => endpoint_key(self.destination()),
            "translated" => endpoint_key(self.translated()),
            "interface" => text(self.interface()),
            "state" => text(self.state()),
            "received" => number(self.received()),
            "sent" => number(self.sent()),
            _ => endpoint_key(self.source()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.texts()
            .into_iter()
            .flatten()
            .any(|text| text.to_lowercase().contains(needle))
    }
}

/// The sort key of an `address:port` endpoint: IPv4 endpoints by address, then port; any
/// other as text.
fn endpoint_key(value: Option<&str>) -> SortKey {
    let Some(text) = value else {
        return SortKey::Missing;
    };
    let (address, port) = text.rsplit_once(':').unwrap_or((text, "0"));
    match (address.parse::<Ipv4Addr>(), port.parse::<u16>()) {
        (Ok(host), Ok(number)) => SortKey::Number(
            i128::from(u32::from(host))
                .saturating_mul(0x1_0000)
                .saturating_add(i128::from(number)),
        ),
        (Ok(_) | Err(_), _) => SortKey::text(text),
    }
}

#[cfg(test)]
#[path = "session_rows_tests.rs"]
mod tests;
