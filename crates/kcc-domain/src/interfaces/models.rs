//! Tolerant interface response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Interface summary returned by `show interface`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Interface {
    /// Stable interface identifier.
    pub id: Option<String>,
    /// Operator-visible description.
    pub description: Option<String>,
    /// Router interface type.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Physical or logical link state.
    pub link: Option<String>,
    /// Administrative state.
    pub state: Option<String>,
    /// Primary address, when present.
    pub address: Option<String>,
    /// Whether this interface participates in global routing.
    pub global: Option<bool>,
    /// Whether this interface supplies the default gateway.
    pub defaultgw: Option<bool>,
    /// Global-routing priority, when reported.
    pub priority: Option<u32>,
    /// Interface security zone.
    #[serde(rename = "security-level")]
    pub security_level: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Interface counter set.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct InterfaceStatistics {
    /// Stable interface identifier.
    pub id: Option<String>,
    /// Received bytes.
    pub rxbytes: Option<u64>,
    /// Transmitted bytes.
    pub txbytes: Option<u64>,
    /// Received packets.
    pub rxpackets: Option<u64>,
    /// Transmitted packets.
    pub txpackets: Option<u64>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Traffic-history response.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct TrafficHistory {
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
