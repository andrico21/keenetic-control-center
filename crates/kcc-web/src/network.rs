//! Network facts of a snapshot: WAN connections, radios, access points and the Internet
//! state, as the dashboard lists them.

use core::net::Ipv4Addr;

use kcc_app::poller::{Snapshot, wan_interface_ids};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::capabilities::RouterInfo;
use serde_json::Value;

/// One Internet-facing connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WanRow {
    /// Interface id.
    id: String,
    /// Description, or the id when the router has none.
    label: String,
    /// IPv4 address with prefix length, or empty.
    address: String,
    /// Whether the link is up.
    up: bool,
}

impl WanRow {
    /// Interface id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Description or id.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Address with prefix length, or empty.
    pub(crate) fn address(&self) -> &str {
        &self.address
    }

    /// Whether the link is up.
    pub(crate) const fn up(&self) -> bool {
        self.up
    }
}

/// One radio and its bands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RadioRow {
    /// Radio id, such as `WifiMaster0`.
    id: String,
    /// Bands as reported, comma-separated, or empty.
    bands: String,
}

impl RadioRow {
    /// Radio id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Bands, or empty.
    pub(crate) fn bands(&self) -> &str {
        &self.bands
    }
}

/// One access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessPointRow {
    /// Interface id, such as `WifiMaster0/AccessPoint0`.
    id: String,
    /// Network name.
    ssid: String,
    /// Whether the access point is enabled.
    up: bool,
}

impl AccessPointRow {
    /// Interface id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Network name.
    pub(crate) fn ssid(&self) -> &str {
        &self.ssid
    }

    /// Whether the access point is enabled.
    pub(crate) const fn up(&self) -> bool {
        self.up
    }
}

/// The radios of a detected router, with their bands as reported.
pub(crate) fn radios(info: &RouterInfo) -> Vec<RadioRow> {
    info.interfaces
        .iter()
        .flat_map(|inventory| inventory.radios.iter())
        .map(|radio| RadioRow {
            id: radio.id.clone(),
            bands: radio.bands.as_deref().unwrap_or_default().join(", "),
        })
        .collect()
}

/// The access points of a `show interface` response, in response order.
pub(crate) fn access_points(interfaces_summary: &Value) -> Vec<AccessPointRow> {
    interfaces(interfaces_summary)
        .filter(|entry| text(entry.get("type")).as_deref() == Some("AccessPoint"))
        .filter_map(|entry| {
            Some(AccessPointRow {
                id: text(entry.get("id"))?,
                ssid: text(entry.get("ssid")).unwrap_or_default(),
                up: text(entry.get("state")).as_deref() == Some("up"),
            })
        })
        .collect()
}

/// The Internet state: the router's own check when reported, otherwise the link state of
/// its WAN connections.
pub(crate) fn internet(snapshot: &Snapshot) -> MessageKey {
    let reported = snapshot
        .internet
        .get("internet")
        .or_else(|| snapshot.internet.pointer("/status/internet"))
        .and_then(Value::as_bool);
    match reported {
        Some(true) => keys::WEB_INTERNET_CONNECTED,
        Some(false) => keys::WEB_INTERNET_DISCONNECTED,
        None => {
            let rows = wan_rows(&snapshot.interfaces_summary);
            match (rows.is_empty(), rows.iter().any(WanRow::up)) {
                (true, _) => keys::WEB_INTERNET_UNKNOWN,
                (false, true) => keys::WEB_INTERNET_WAN_UP,
                (false, false) => keys::WEB_INTERNET_WAN_DOWN,
            }
        }
    }
}

/// The WAN connections of a `show interface` response, in response order.
pub(crate) fn wan_rows(interfaces_summary: &Value) -> Vec<WanRow> {
    let wan = wan_interface_ids(interfaces_summary);
    interfaces(interfaces_summary)
        .filter_map(|entry| {
            let id = text(entry.get("id"))?;
            if !wan.contains(&id) {
                return None;
            }
            let address = text(entry.get("address"))
                .map(|address| match prefix(entry.get("mask")) {
                    Some(bits) => format!("{address}/{bits}"),
                    None => address,
                })
                .unwrap_or_default();
            Some(WanRow {
                label: text(entry.get("description"))
                    .filter(|description| !description.is_empty())
                    .unwrap_or_else(|| id.clone()),
                id,
                address,
                up: text(entry.get("link")).as_deref() == Some("up"),
            })
        })
        .collect()
}

/// Every interface object of a `show interface` response (an object or an array).
fn interfaces(summary: &Value) -> impl Iterator<Item = &Value> {
    let (keyed, listed) = match summary {
        Value::Object(map) => (Some(map.values()), None),
        Value::Array(items) => (None, Some(items.iter())),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => (None, None),
    };
    keyed
        .into_iter()
        .flatten()
        .chain(listed.into_iter().flatten())
}

/// The prefix length of a dotted IPv4 netmask.
fn prefix(mask: Option<&Value>) -> Option<u32> {
    let parsed: Ipv4Addr = mask?.as_str()?.parse().ok()?;
    Some(u32::from(parsed).count_ones())
}

/// A JSON string value as owned text.
fn text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}
