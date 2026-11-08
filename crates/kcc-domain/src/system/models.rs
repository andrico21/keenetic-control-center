//! Tolerant system response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tolerant firmware identity.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Version {
    /// Firmware title.
    pub title: Option<String>,
    /// Firmware release string.
    pub release: Option<String>,
    /// Marketing model.
    pub model: Option<String>,
    /// Hardware identifier.
    pub hw_id: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant system state.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SystemState {
    /// Router host name.
    pub hostname: Option<String>,
    /// Router DNS domain name.
    pub domainname: Option<String>,
    /// Uptime as reported by firmware.
    pub uptime: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant clock state.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ClockDate {
    /// Calendar year.
    pub year: Option<u16>,
    /// Calendar month.
    pub month: Option<u8>,
    /// Calendar day.
    pub day: Option<u8>,
    /// Hour in local time.
    pub hour: Option<u8>,
    /// Minute in local time.
    pub min: Option<u8>,
    /// Second in local time.
    pub sec: Option<u8>,
    /// Timezone object.
    pub tz: Option<Value>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant NTP state.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NtpStatus {
    /// Synchronization state, when reported.
    pub status: Option<String>,
    /// Selected server, when reported.
    pub server: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant operating mode.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SystemMode {
    /// Router mode name.
    pub mode: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
