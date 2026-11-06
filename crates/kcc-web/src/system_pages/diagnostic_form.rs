//! The diagnostic form: which tool, and the fields each tool takes, checked and turned into
//! the body of the tool's catalog command before anything is sent.

use core::{net::Ipv4Addr, ops::RangeInclusive};

use kcc_domain::diagnostics::DiagnosticKind;
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Map, Value};

use super::shared::value;

/// Longest host name accepted, in bytes.
const HOST_BYTES: usize = 253;

/// Longest interface name accepted, in bytes.
const INTERFACE_BYTES: usize = 32;

/// A diagnostic tool the page runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tool {
    /// Echo requests to a host.
    Ping,
    /// The route to a host.
    Traceroute,
    /// ARP requests to an address on one interface.
    Arping,
    /// Throughput to an iperf3 server.
    Iperf3,
}

impl Tool {
    /// Every tool, in form order.
    pub(crate) const ALL: [Self; 4] = [Self::Ping, Self::Traceroute, Self::Arping, Self::Iperf3];

    /// The tool named by the form value `name`.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// The form value.
    pub(crate) const fn name(self) -> &'static str {
        self.kind().name()
    }

    /// The domain's diagnostic.
    pub(crate) const fn kind(self) -> DiagnosticKind {
        match self {
            Self::Ping => DiagnosticKind::Ping,
            Self::Traceroute => DiagnosticKind::Traceroute,
            Self::Arping => DiagnosticKind::Arping,
            Self::Iperf3 => DiagnosticKind::Iperf3,
        }
    }

    /// The tool's label, also its job panel's title.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Ping => keys::WEB_SYSTEM_DIAG_PING,
            Self::Traceroute => keys::WEB_SYSTEM_DIAG_TRACEROUTE,
            Self::Arping => keys::WEB_SYSTEM_DIAG_ARPING,
            Self::Iperf3 => keys::WEB_SYSTEM_DIAG_IPERF3,
        }
    }

    /// Stable audit action id.
    pub(crate) const fn audit(self) -> &'static str {
        match self {
            Self::Ping => "web.diagnostics_ping",
            Self::Traceroute => "web.diagnostics_traceroute",
            Self::Arping => "web.diagnostics_arping",
            Self::Iperf3 => "web.diagnostics_iperf3",
        }
    }

    /// The body of the tool's catalog command from the submitted `pairs`.
    ///
    /// # Errors
    ///
    /// Returns the message saying which field is not valid.
    pub(crate) fn body(self, pairs: &[(String, String)]) -> Result<Value, MessageKey> {
        let mut body = Map::new();
        match self {
            Self::Ping | Self::Traceroute | Self::Iperf3 => {
                let host = value(pairs, "host").unwrap_or_default();
                if !is_host(host) {
                    return Err(keys::WEB_SYSTEM_DIAG_HOST_ERROR);
                }
                drop(body.insert("host".to_owned(), Value::String(host.to_owned())));
            }
            Self::Arping => {
                let address = value(pairs, "address").unwrap_or_default();
                let interface = value(pairs, "interface").unwrap_or_default();
                if address.parse::<Ipv4Addr>().is_err() {
                    return Err(keys::WEB_SYSTEM_DIAG_ADDRESS_ERROR);
                }
                if !is_interface(interface) {
                    return Err(keys::WEB_SYSTEM_DIAG_INTERFACE_ERROR);
                }
                drop(body.insert("address".to_owned(), Value::String(address.to_owned())));
                drop(body.insert(
                    "source-interface".to_owned(),
                    Value::String(interface.to_owned()),
                ));
            }
        }
        for (field, argument, range) in self.numbers() {
            if let Some(text) = value(pairs, field).filter(|text| !text.is_empty()) {
                let number = text
                    .parse::<u32>()
                    .ok()
                    .filter(|number| range.contains(number))
                    .ok_or(keys::WEB_SYSTEM_DIAG_NUMBER_ERROR)?;
                drop(body.insert((*argument).to_owned(), Value::from(number)));
            }
        }
        Ok(Value::Object(body))
    }

    /// The optional numeric fields of the tool: form name, catalog argument, valid range.
    const fn numbers(self) -> &'static [(&'static str, &'static str, RangeInclusive<u32>)] {
        match self {
            Self::Ping | Self::Arping => &[("count", "count", 1..=100)],
            Self::Traceroute => &[("max_ttl", "max-ttl", 1..=64)],
            Self::Iperf3 => &[("port", "port", 1..=0xFFFF), ("time", "time", 1..=60)],
        }
    }
}

/// Whether `value` is a host name or an IPv4 or IPv6 address the router's tools take.
fn is_host(value: &str) -> bool {
    (1..=HOST_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
}

/// Whether `value` names a router interface, such as `Bridge0` or `WifiMaster0/AccessPoint0`.
fn is_interface(value: &str) -> bool {
    (1..=INTERFACE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'/')
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::keys;
    use serde_json::json;

    use super::Tool;

    /// `pairs` as owned form pairs.
    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn each_tool_takes_its_fields_and_refuses_bad_ones() {
        assert_eq!(
            Tool::Ping.body(&form(&[
                ("host", "192.0.2.1"),
                ("count", "3"),
                ("port", "9")
            ])),
            Ok(json!({"host": "192.0.2.1", "count": 3_u32})),
            "ping ignores the other tools' fields"
        );
        assert_eq!(
            Tool::Arping.body(&form(&[("address", "192.0.2.1"), ("interface", "Bridge0")])),
            Ok(json!({"address": "192.0.2.1", "source-interface": "Bridge0"})),
            "arping"
        );
        assert_eq!(
            Tool::Ping.body(&form(&[("host", "bad host")])),
            Err(keys::WEB_SYSTEM_DIAG_HOST_ERROR),
            "host"
        );
        assert_eq!(
            Tool::Iperf3.body(&form(&[("host", "iperf.example"), ("time", "600")])),
            Err(keys::WEB_SYSTEM_DIAG_NUMBER_ERROR),
            "time range"
        );
        assert_eq!(Tool::from_name("iperf3"), Some(Tool::Iperf3), "names");
        assert_eq!(Tool::from_name("nmap"), None, "only these tools");
    }
}
