//! The devices connected to Wi-Fi, as the Wi-Fi page lists them: a sortable, filterable
//! table of their MAC address, access point, network name, signal and rates.

use fluent_bundle::FluentArgs;
use kcc_domain::{
    DomainError, RouterCtx,
    wifi::{self, Station},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// One connected device.
#[derive(Debug, Clone)]
pub(crate) struct StationRow {
    /// MAC address.
    mac: String,
    /// Access point it is connected to.
    interface: Option<String>,
    /// Network name.
    ssid: Option<String>,
    /// Signal in dBm.
    rssi: Option<i16>,
    /// Receive rate in Mbit/s.
    rx: Option<u64>,
    /// Transmit rate in Mbit/s.
    tx: Option<u64>,
}

impl StationRow {
    /// The row of `station`.
    fn new(station: Station) -> Self {
        Self {
            mac: station.mac.unwrap_or_default(),
            interface: station.interface,
            ssid: station.ssid,
            rssi: station.rssi,
            rx: station.rx_rate,
            tx: station.tx_rate,
        }
    }

    /// MAC address.
    pub(crate) fn mac(&self) -> &str {
        &self.mac
    }

    /// Access point.
    pub(crate) fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Network name.
    pub(crate) fn ssid(&self) -> Option<&str> {
        self.ssid.as_deref()
    }

    /// The signal in `locale`, such as `-42 dBm`.
    pub(crate) fn signal_text(&self, locale: Locale) -> Option<String> {
        self.rssi
            .map(|value| with_value(locale, keys::WEB_WIFI_SIGNAL_VALUE, i64::from(value)))
    }

    /// The receive rate in `locale`.
    pub(crate) fn rx_text(&self, locale: Locale) -> Option<String> {
        self.rx.map(|value| rate(locale, value))
    }

    /// The transmit rate in `locale`.
    pub(crate) fn tx_text(&self, locale: Locale) -> Option<String> {
        self.tx.map(|value| rate(locale, value))
    }
}

impl Row for StationRow {
    const COLUMNS: &'static [&'static str] = &["mac", "access-point", "ssid", "signal", "rx", "tx"];
    const DEFAULT: Sort = Sort::new("signal", Direction::Descending);

    fn key(&self, column: &str) -> SortKey {
        let text_key = |value: Option<&str>| value.map_or(SortKey::Missing, SortKey::text);
        let number = |value: Option<i128>| value.map_or(SortKey::Missing, SortKey::Number);
        match column {
            "access-point" => text_key(self.interface.as_deref()),
            "ssid" => text_key(self.ssid.as_deref()),
            "signal" => number(self.rssi.map(i128::from)),
            "rx" => number(self.rx.map(i128::from)),
            "tx" => number(self.tx.map(i128::from)),
            _ => SortKey::text(&self.mac),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(self.mac.as_str()),
            self.interface.as_deref(),
            self.ssid.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }
}

/// The devices connected to the router of `domain`.
///
/// # Errors
///
/// Returns the router's error.
// cancel-safe: reads only.
pub(crate) async fn stations(domain: &RouterCtx) -> Result<Vec<StationRow>, DomainError> {
    Ok(wifi::read_stations(domain)
        .await?
        .into_iter()
        .map(StationRow::new)
        .collect())
}

/// `key` in `locale` with `value` as `$value`.
fn with_value(locale: Locale, key: MessageKey, value: i64) -> String {
    let mut args = FluentArgs::new();
    args.set("value", value);
    tr(locale, key, Some(&args))
}

/// A rate of `value` Mbit/s in `locale`.
fn rate(locale: Locale, value: u64) -> String {
    let mut args = FluentArgs::new();
    args.set("value", value);
    tr(locale, keys::WEB_WIFI_RATE_VALUE, Some(&args))
}
