//! Wi-Fi as the pages show it: radios and access points.
//!
//! Every value is read through the Wi-Fi and interfaces domains; an access point's stored
//! password is reported only as set or not, never shown. Its segment is the bridge whose
//! configuration includes it, when the router reports that.

use alloc::collections::BTreeMap;

use kcc_domain::{
    DomainError, RouterCtx,
    wifi::{self, AccessPoint, Radio},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::{Map, Value, json};

use crate::net_change::scalar;

/// One radio.
#[derive(Debug, Clone)]
pub(crate) struct RadioRow {
    /// Radio id, such as `WifiMaster0`.
    id: String,
    /// Band, such as `2.4`.
    band: Option<String>,
    /// Channel.
    channel: Option<String>,
    /// Channel width.
    width: Option<String>,
    /// Transmit power.
    power: Option<String>,
    /// Country code.
    country: Option<String>,
}

impl RadioRow {
    /// The row of `radio`, reported under `id`.
    fn new(id: String, radio: &Radio) -> Self {
        let first = |names: &[&str]| names.iter().find_map(|name| scalar(radio.extra.get(*name)));
        Self {
            id,
            band: radio.band.clone(),
            channel: scalar(radio.channel.as_ref()),
            width: first(&["bandwidth", "channel-width", "width"]),
            power: first(&["power"]),
            country: first(&["country-code", "country"]),
        }
    }

    /// Radio id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Band.
    pub(crate) fn band(&self) -> Option<&str> {
        self.band.as_deref()
    }

    /// Channel.
    pub(crate) fn channel(&self) -> Option<&str> {
        self.channel.as_deref()
    }

    /// Channel width.
    pub(crate) fn width(&self) -> Option<&str> {
        self.width.as_deref()
    }

    /// Transmit power.
    pub(crate) fn power(&self) -> Option<&str> {
        self.power.as_deref()
    }

    /// Country code.
    pub(crate) fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }
}

/// One access point.
#[derive(Debug, Clone)]
pub(crate) struct ApRow {
    /// Interface id, such as `WifiMaster0/AccessPoint0`.
    id: String,
    /// Network name.
    ssid: Option<String>,
    /// Whether it is enabled, when reported.
    enabled: Option<bool>,
    /// Whether the network name is hidden, when reported.
    hidden: Option<bool>,
    /// Schedule.
    schedule: Option<String>,
    /// Security mode, as reported.
    security: Option<String>,
    /// Whether a Wi-Fi password is stored.
    password: bool,
    /// The bridge that includes it.
    segment: Option<String>,
}

impl ApRow {
    /// The row of `point`, reported under `id`, in `segment`, `password` saying whether a
    /// Wi-Fi password is stored.
    fn new(id: String, point: &AccessPoint, segment: Option<String>) -> Self {
        Self {
            ssid: point.ssid.clone(),
            enabled: point.state.as_deref().map(|state| state == "up"),
            hidden: point.hide_ssid,
            schedule: point.schedule.clone().filter(|name| !name.is_empty()),
            security: scalar(point.extra.get("encryption")),
            password: point.psk_present,
            segment,
            id,
        }
    }

    /// Interface id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Network name.
    pub(crate) fn ssid(&self) -> Option<&str> {
        self.ssid.as_deref()
    }

    /// Whether it is enabled, when reported.
    pub(crate) const fn enabled(&self) -> Option<bool> {
        self.enabled
    }

    /// Whether the network name is hidden, when reported.
    pub(crate) const fn hidden(&self) -> Option<bool> {
        self.hidden
    }

    /// Schedule.
    pub(crate) fn schedule(&self) -> Option<&str> {
        self.schedule.as_deref()
    }

    /// Security mode.
    pub(crate) fn security(&self) -> Option<&str> {
        self.security.as_deref()
    }

    /// The bridge that includes it.
    pub(crate) fn segment(&self) -> Option<&str> {
        self.segment.as_deref()
    }

    /// The state in `locale`.
    pub(crate) fn state_text(&self, locale: Locale) -> Option<String> {
        self.enabled.map(|enabled| {
            text(
                locale,
                if enabled {
                    keys::COMMON_ENABLED
                } else {
                    keys::COMMON_DISABLED
                },
            )
        })
    }

    /// Whether the network name is hidden, in `locale`.
    pub(crate) fn hidden_text(&self, locale: Locale) -> Option<String> {
        self.hidden.map(|hidden| {
            text(
                locale,
                if hidden {
                    keys::COMMON_YES
                } else {
                    keys::COMMON_NO
                },
            )
        })
    }

    /// Whether a Wi-Fi password is stored, in `locale`.
    pub(crate) fn password_text(&self, locale: Locale) -> String {
        text(
            locale,
            if self.password {
                keys::WEB_INTERNET_SET
            } else {
                keys::WEB_INTERNET_NOT_SET
            },
        )
    }
}

/// The radios of the router of `domain`.
///
/// # Errors
///
/// Returns the router's error.
// cancel-safe: reads only.
pub(crate) async fn radios(domain: &RouterCtx) -> Result<Vec<RadioRow>, DomainError> {
    Ok(wifi::read_radios(domain)
        .await?
        .into_iter()
        .map(|(id, radio)| RadioRow::new(id, &radio))
        .collect())
}

/// The access points of the router of `domain`, with their segments.
///
/// # Errors
///
/// Returns the router's error.
// cancel-safe: reads only.
pub(crate) async fn access_points(domain: &RouterCtx) -> Result<Vec<ApRow>, DomainError> {
    let found = wifi::read_access_points(domain).await?;
    let segments = segments(domain).await;
    Ok(found
        .into_iter()
        .map(|(id, point)| {
            let segment = segments.get(&id).cloned();
            ApRow::new(id, &point, segment)
        })
        .collect())
}

/// Which bridge includes each interface, from the running configuration; empty when the
/// router does not report it.
// cancel-safe: a read.
async fn segments(domain: &RouterCtx) -> BTreeMap<String, String> {
    let Ok(response) = domain.client.show_rc(json!({"interface": {}})).await else {
        return BTreeMap::new();
    };
    let tree = response
        .configuration_tree()
        .get("interface")
        .and_then(Value::as_object);
    tree.map_or_else(BTreeMap::new, included)
}

/// Every member of a bridge's `include` list in `tree`, with its bridge.
fn included(tree: &Map<String, Value>) -> BTreeMap<String, String> {
    tree.iter()
        .flat_map(|(bridge, config)| {
            config
                .get("include")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.get("interface").and_then(Value::as_str))
                .map(move |member| (member.to_owned(), bridge.clone()))
        })
        .collect()
}

/// `key` in `locale`.
fn text(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}
