//! Secret-free Wi-Fi response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Wi-Fi access point.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
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
    /// Whether a WPA pre-shared key is stored, by presence only; never serialized.
    #[serde(skip_serializing)]
    pub psk_present: bool,
    /// Unmodelled non-secret fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Internal access-point response that owns authentication only until it is discarded.
#[derive(Default, Deserialize)]
#[serde(default)]
struct WireAccessPoint {
    /// Stable interface identifier.
    id: Option<String>,
    /// Broadcast network name.
    ssid: Option<String>,
    /// Administrative state.
    state: Option<String>,
    /// Whether SSID broadcast is hidden.
    #[serde(rename = "hide-ssid")]
    hide_ssid: Option<bool>,
    /// Assigned schedule.
    schedule: Option<String>,
    /// Authentication material discarded at the read boundary.
    authentication: Option<Value>,
    /// Unmodelled non-authentication fields.
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for AccessPoint {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireAccessPoint::deserialize(deserializer)?;
        Ok(Self {
            id: wire.id,
            ssid: wire.ssid,
            state: wire.state,
            hide_ssid: wire.hide_ssid,
            schedule: wire.schedule,
            psk_present: wire
                .authentication
                .as_ref()
                .and_then(|authentication| authentication.get("wpa-psk"))
                .is_some(),
            extra: wire.extra,
        })
    }
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
    /// Access-point interface; the router names it `ap`.
    #[serde(alias = "ap")]
    pub interface: Option<String>,
    /// Associated SSID.
    pub ssid: Option<String>,
    /// Received signal strength.
    pub rssi: Option<i16>,
    /// Receive rate.
    #[serde(rename = "rx-rate", alias = "rxrate")]
    pub rx_rate: Option<u64>,
    /// Transmit rate.
    #[serde(rename = "tx-rate", alias = "txrate")]
    pub tx_rate: Option<u64>,
    /// Bytes received from the station.
    #[serde(rename = "rx-bytes", alias = "rxbytes")]
    pub rx_bytes: Option<u64>,
    /// Bytes sent to the station.
    #[serde(rename = "tx-bytes", alias = "txbytes")]
    pub tx_bytes: Option<u64>,
    /// Seconds since the station associated.
    pub uptime: Option<u64>,
    /// Unmodelled station fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
