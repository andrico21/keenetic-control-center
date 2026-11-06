//! System, identity, Internet-check and configuration-state families.
#![expect(
    clippy::float_arithmetic,
    reason = "unit conversions of router-reported values into Prometheus f64 samples"
)]

use kcc_app::poller::Snapshot;
use kcc_rci::capabilities::{Brand, RouterInfo};
use serde_json::Value;

use super::{
    json::{flag, gauge, number, text},
    sink::Sink,
};

/// Keenetic reports memory in KiB.
const KIB: f64 = 1024.0;

/// `show internet status` members and their `check` label values.
const INTERNET_CHECKS: &[(&str, &str)] = &[
    ("internet", "internet"),
    ("gateway-accessible", "gateway"),
    ("dns-accessible", "dns"),
    ("host-accessible", "host"),
    ("captive-accessible", "captive"),
];

/// Renders the light system families of one fresh snapshot.
pub(super) fn light(sink: &Sink, router: &str, snapshot: &Snapshot) {
    let labels = [router];
    sink.put(
        "keenetic_poll_duration_seconds",
        &labels,
        snapshot.poll_duration.as_secs_f64(),
    );
    let system = &snapshot.system;
    if let Some(load) = number(system, "cpuload") {
        sink.put("keenetic_cpu_load_ratio", &labels, load / 100.0);
    }
    for (key, name) in [
        ("memtotal", "keenetic_memory_total_bytes"),
        ("memfree", "keenetic_memory_free_bytes"),
        ("memcache", "keenetic_memory_cache_bytes"),
        ("membuffers", "keenetic_memory_buffers_bytes"),
    ] {
        if let Some(kib) = number(system, key) {
            sink.put(name, &labels, kib * KIB);
        }
    }
    if let Some((used, total)) = text(system, "swap").and_then(ratio) {
        sink.put("keenetic_swap_total_bytes", &labels, total * KIB);
        sink.put(
            "keenetic_swap_free_bytes",
            &labels,
            (total - used).max(0.0) * KIB,
        );
    }
    if let Some(uptime) = number(system, "uptime") {
        sink.put("keenetic_uptime_seconds", &labels, uptime);
    }
    if let (Some(total), Some(free)) = (number(system, "conntotal"), number(system, "connfree")) {
        sink.put("keenetic_conntrack_max", &labels, total);
        sink.put(
            "keenetic_conntrack_entries",
            &labels,
            (total - free).max(0.0),
        );
    }
    for (key, check) in INTERNET_CHECKS {
        if let Some(reachable) = flag(&snapshot.internet_status, key) {
            sink.put(
                "keenetic_internet_reachable",
                &[router, check],
                gauge(reachable),
            );
        }
    }
    configuration(sink, router, &snapshot.last_change);
    if let Some(available) = snapshot.update_available {
        sink.put(
            "keenetic_firmware_update_available",
            &labels,
            gauge(available),
        );
    }
}

/// `show last-change`: unsaved configuration and the fail-safe timer.
fn configuration(sink: &Sink, router: &str, last_change: &Value) {
    if let Some(unsaved) = flag(last_change, "unsaved") {
        sink.put("keenetic_config_unsaved", &[router], gauge(unsaved));
    }
    if let Some(armed) = last_change
        .get("fail-safe")
        .and_then(|fail_safe| flag(fail_safe, "active"))
    {
        sink.put("keenetic_failsafe_armed", &[router], gauge(armed));
    }
}

/// `keenetic_info` from the detected identity (heavy cadence).
pub(super) fn info(sink: &Sink, router: &str, info: &RouterInfo) {
    let version = &info.version;
    let firmware = info.firmware.map_or_else(
        || {
            version
                .title
                .clone()
                .or_else(|| version.release.clone())
                .unwrap_or_default()
        },
        |firmware| firmware.to_string(),
    );
    sink.put(
        "keenetic_info",
        &[
            router,
            version.model.as_deref().unwrap_or_default(),
            version.hw_id.as_deref().unwrap_or_default(),
            brand(info.brand),
            &firmware,
            version.region.as_deref().unwrap_or_default(),
        ],
        1.0,
    );
}

/// Stable lowercase brand label.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Brand is non_exhaustive in kcc-rci; a new brand reads as unknown until mapped"
)]
const fn brand(brand: Brand) -> &'static str {
    match brand {
        Brand::Keenetic => "keenetic",
        Brand::Netcraze => "netcraze",
        _ => "unknown",
    }
}

/// Parses `"<used>/<total>"`.
fn ratio(text: &str) -> Option<(f64, f64)> {
    let (used, total) = text.split_once('/')?;
    Some((used.trim().parse().ok()?, total.trim().parse().ok()?))
}
