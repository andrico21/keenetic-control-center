//! Gauges of the router health facts: CPU load and memory use.

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};
use serde_json::Value;

use crate::traffic::number;

/// A gauge: a whole percentage and the text that states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gauge {
    /// 0 to 100.
    percent: u64,
    /// The value as text, such as `7%` or `128 MB of 256 MB`.
    text: String,
}

impl Gauge {
    /// CPU load as reported, capped at 100.
    pub(crate) fn cpu(load: u64, locale: Locale) -> Self {
        let percent = load.min(100);
        Self {
            percent,
            text: format::percent(locale, percent),
        }
    }

    /// 0 to 100.
    pub(crate) const fn percent(&self) -> u64 {
        self.percent
    }

    /// The value as text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// Memory in use (`memtotal - memfree`, both in KiB) against the total.
pub(crate) fn memory(system: &Value, locale: Locale) -> Option<Gauge> {
    let total = system
        .get("memtotal")
        .and_then(number)
        .filter(|kib| *kib > 0)?;
    let used = total.saturating_sub(system.get("memfree").and_then(number)?);
    let percent = used
        .saturating_mul(100)
        .saturating_add(total.checked_div(2).unwrap_or(0))
        .checked_div(total)?;
    let mut args = FluentArgs::new();
    args.set("current", format::bytes(locale, used.saturating_mul(1024)));
    args.set("total", format::bytes(locale, total.saturating_mul(1024)));
    Some(Gauge {
        percent,
        text: tr(locale, keys::WEB_MEMORY_USAGE, Some(&args)),
    })
}
