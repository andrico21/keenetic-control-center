//! Secret-free Wi-Fi response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wi-Fi access point.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct AccessPoint {
    /// Stable interface identifier.
    pub id: Option<String>,
    /// Broadcast network name.
    pub ssid: Option<String>,
    /// Administrative state.
    pub state: Option<String>,
    /// Whether SSID broadcast is hidden.
    #[serde(rename = "hide-ssid")]
    pub hide_ssid: Option<bool>,
    /// Assigned schedule.
    pub schedule: Option<String>,
    /// Unmodelled non-secret fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Wi-Fi radio with band derived from `show interface`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Radio {
    /// Stable radio identifier.
    pub id: Option<String>,
    /// Router interface type.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Reported frequency band.
    pub band: Option<String>,
    /// Current channel.
    pub channel: Option<Value>,
    /// Unmodelled radio fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Associated Wi-Fi station.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Station {
    /// Station MAC address.
    pub mac: Option<String>,
    /// Access-point interface.
    pub interface: Option<String>,
    /// Associated SSID.
    pub ssid: Option<String>,
    /// Received signal strength.
    pub rssi: Option<i16>,
    /// Receive rate.
    #[serde(rename = "rx-rate")]
    pub rx_rate: Option<u64>,
    /// Transmit rate.
    #[serde(rename = "tx-rate")]
    pub tx_rate: Option<u64>,
    /// Unmodelled station fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Stored NS3 presence and encoded-length validation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Ns3Presence {
    /// Whether an NS3 value exists.
    pub present: bool,
    /// Encoded byte length when present.
    pub encoded_length: Option<usize>,
    /// Whether the encoded length is plausible for NS3 storage.
    pub plausible_length: bool,
}

impl Ns3Presence {
    /// Creates an NS3 presence summary.
    #[inline]
    #[must_use]
    pub const fn new(present: bool, encoded_length: Option<usize>, plausible_length: bool) -> Self {
        Self {
            present,
            encoded_length,
            plausible_length,
        }
    }
}
