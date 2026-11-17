//! Tolerant interface response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
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
    /// Unmodelled router fields, without the credentials `show interface` carries:
    /// `authentication` keeps only which credentials are stored (each `true`), and `ns3`
    /// members are dropped.
    #[serde(flatten, deserialize_with = "without_credentials")]
    pub extra: BTreeMap<String, Value>,
}

/// Unmodelled interface fields at the read boundary: `authentication` reduced to the
/// names of the stored credentials, and every `ns3` member removed.
///
/// # Errors
///
/// Returns the deserializer's error when the unmodelled interface fields are not a map of JSON
/// values.
fn without_credentials<'de, D>(deserializer: D) -> Result<BTreeMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut extra = BTreeMap::<String, Value>::deserialize(deserializer)?;
    drop(extra.remove("ns3"));
    extra.values_mut().for_each(drop_ns3);
    if let Some(Value::Object(stored)) = extra.remove("authentication") {
        let presence = stored
            .into_iter()
            .map(|(name, _secret)| (name, Value::Bool(true)));
        drop(extra.insert(
            "authentication".to_owned(),
            Value::Object(presence.collect()),
        ));
    }
    Ok(extra)
}

/// Removes every `ns3` member below `value`.
fn drop_ns3(value: &mut Value) {
    match value {
        Value::Object(object) => {
            drop(object.remove("ns3"));
            object.values_mut().for_each(drop_ns3);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_ns3),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
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
