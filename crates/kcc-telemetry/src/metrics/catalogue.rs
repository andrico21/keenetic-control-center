//! The metric catalogue: every family kcc exports, with its type, help text and labels.
// allow: SIZE_OK - pure data table, one entry per exported metric family

/// Prometheus metric type of a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricKind {
    /// A value that can go up and down.
    Gauge,
    /// A monotonically increasing total.
    Counter,
    /// A bucketed distribution.
    Histogram,
}

impl MetricKind {
    /// The `# TYPE` keyword.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Counter => "counter",
            Self::Histogram => "histogram",
        }
    }
}

/// When a family is present in a scrape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Presence {
    /// Always present while a router is watched and its data is fresh.
    Always,
    /// Present only when the router reports the underlying value.
    WhenReported,
    /// Present only with `[metrics] per_client = true`.
    PerClient,
    /// A kcc self-metric, present once the event it counts happened.
    SelfMetric,
}

/// One metric family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Family {
    /// Full metric name.
    pub name: &'static str,
    /// Metric type.
    pub kind: MetricKind,
    /// `# HELP` text.
    pub help: &'static str,
    /// Variable labels in exposition order.
    pub labels: &'static [&'static str],
    /// When the family appears.
    pub presence: Presence,
}

/// Shorthand constructor for the static table.
const fn family(
    name: &'static str,
    kind: MetricKind,
    help: &'static str,
    labels: &'static [&'static str],
    presence: Presence,
) -> Family {
    Family {
        name,
        kind,
        help,
        labels,
        presence,
    }
}

use MetricKind::{Counter, Gauge, Histogram};
use Presence::{Always, PerClient, SelfMetric, WhenReported};

/// Router label only.
const ROUTER: &[&str] = &["router"];
/// Router and interface labels.
const ROUTER_INTERFACE: &[&str] = &["router", "interface"];
/// Router and client labels.
const ROUTER_CLIENT: &[&str] = &["router", "client"];

/// Every exported family, router families first, then kcc self-metrics.
pub const FAMILIES: &[Family] = &[
    family(
        "keenetic_up",
        Gauge,
        "1 when the cached router data is fresh, 0 when it is missing or older than 3 polling intervals.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_poll_duration_seconds",
        Gauge,
        "Wall time of the last completed polling round.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_info",
        Gauge,
        "Router identity; always 1.",
        &["router", "model", "hw_id", "brand", "firmware", "region"],
        Always,
    ),
    family(
        "keenetic_cpu_load_ratio",
        Gauge,
        "CPU load as a ratio of 1.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_memory_total_bytes",
        Gauge,
        "Total memory.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_memory_free_bytes",
        Gauge,
        "Free memory.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_memory_cache_bytes",
        Gauge,
        "Page cache memory.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_memory_buffers_bytes",
        Gauge,
        "Buffer memory.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_swap_total_bytes",
        Gauge,
        "Total swap.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_swap_free_bytes",
        Gauge,
        "Free swap.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_uptime_seconds",
        Gauge,
        "Router uptime.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_conntrack_entries",
        Gauge,
        "Connection-tracking entries in use.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_conntrack_max",
        Gauge,
        "Connection-tracking table size.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_internet_reachable",
        Gauge,
        "1 when the router's Internet check passes.",
        &["router", "check"],
        Always,
    ),
    family(
        "keenetic_interface_up",
        Gauge,
        "1 when the interface state is up.",
        &["router", "interface", "type"],
        Always,
    ),
    family(
        "keenetic_interface_info",
        Gauge,
        "Interface description; always 1.",
        &["router", "interface", "description"],
        Always,
    ),
    family(
        "keenetic_interface_link_up",
        Gauge,
        "1 when the interface link is up.",
        ROUTER_INTERFACE,
        Always,
    ),
    family(
        "keenetic_interface_receive_bytes_total",
        Counter,
        "Bytes received by an up interface.",
        ROUTER_INTERFACE,
        Always,
    ),
    family(
        "keenetic_interface_transmit_bytes_total",
        Counter,
        "Bytes transmitted by an up interface.",
        ROUTER_INTERFACE,
        Always,
    ),
    family(
        "keenetic_interface_receive_packets_total",
        Counter,
        "Packets received by an up interface.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_interface_transmit_packets_total",
        Counter,
        "Packets transmitted by an up interface.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_interface_receive_errors_total",
        Counter,
        "Receive errors of an up interface.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_interface_transmit_errors_total",
        Counter,
        "Transmit errors of an up interface.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_interface_uptime_seconds",
        Gauge,
        "Time since the interface came up.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_radio_temperature_celsius",
        Gauge,
        "Wi-Fi radio temperature.",
        ROUTER_INTERFACE,
        WhenReported,
    ),
    family(
        "keenetic_wifi_clients",
        Gauge,
        "Online clients per access point.",
        &["router", "access_point", "band"],
        Always,
    ),
    family(
        "keenetic_clients",
        Gauge,
        "Known clients by state.",
        &["router", "state"],
        Always,
    ),
    family(
        "keenetic_dhcp_leases",
        Gauge,
        "Active DHCP leases.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_wireguard_peer_last_handshake_seconds",
        Gauge,
        "Seconds since the last WireGuard handshake; peer is the first 8 characters of its public key.",
        &["router", "interface", "peer"],
        WhenReported,
    ),
    family(
        "keenetic_mesh_member_up",
        Gauge,
        "1 when a mesh Wi-Fi system member is online.",
        &["router", "member"],
        WhenReported,
    ),
    family(
        "keenetic_storage_total_bytes",
        Gauge,
        "Size of a storage partition.",
        &["router", "label"],
        WhenReported,
    ),
    family(
        "keenetic_storage_free_bytes",
        Gauge,
        "Free space of a storage partition.",
        &["router", "label"],
        WhenReported,
    ),
    family(
        "keenetic_firmware_update_available",
        Gauge,
        "1 when a firmware update is available (cached flag).",
        ROUTER,
        WhenReported,
    ),
    family(
        "keenetic_config_unsaved",
        Gauge,
        "1 when the running configuration differs from the saved one.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_failsafe_armed",
        Gauge,
        "1 while the configuration fail-safe timer is armed.",
        ROUTER,
        Always,
    ),
    family(
        "keenetic_client_receive_bytes_total",
        Counter,
        "Bytes received from one client.",
        ROUTER_CLIENT,
        PerClient,
    ),
    family(
        "keenetic_client_transmit_bytes_total",
        Counter,
        "Bytes transmitted to one client.",
        ROUTER_CLIENT,
        PerClient,
    ),
    family(
        "keenetic_client_signal_dbm",
        Gauge,
        "Wi-Fi signal strength of one client.",
        ROUTER_CLIENT,
        PerClient,
    ),
    family(
        "keenetic_client_link_speed_mbps",
        Gauge,
        "Wi-Fi link speed of one client.",
        ROUTER_CLIENT,
        PerClient,
    ),
    family(
        "kcc_metrics_series_dropped",
        Gauge,
        "Per-client series not exported at the latest scrape because of per_client_max.",
        ROUTER,
        PerClient,
    ),
    family(
        "kcc_build_info",
        Gauge,
        "kcc build; always 1.",
        &["version"],
        SelfMetric,
    ),
    family(
        "kcc_router_requests_total",
        Counter,
        "RCI requests by outcome.",
        &["router", "outcome"],
        SelfMetric,
    ),
    family(
        "kcc_router_request_duration_seconds",
        Histogram,
        "RCI request duration.",
        ROUTER,
        SelfMetric,
    ),
    family(
        "kcc_router_auth_total",
        Counter,
        "Router login exchanges by scheme and outcome.",
        &["router", "scheme", "outcome"],
        SelfMetric,
    ),
    family(
        "kcc_poller_errors_total",
        Counter,
        "Failed polling rounds.",
        ROUTER,
        SelfMetric,
    ),
    family(
        "kcc_jobs",
        Gauge,
        "Running jobs, and jobs finished since start, by kind and state.",
        &["kind", "state"],
        SelfMetric,
    ),
    family(
        "kcc_web_sessions",
        Gauge,
        "Active Web UI sessions.",
        &[],
        SelfMetric,
    ),
    family(
        "kcc_log_records_received_total",
        Counter,
        "Router log records accepted by the collector.",
        ROUTER,
        SelfMetric,
    ),
    family(
        "kcc_log_records_forwarded_total",
        Counter,
        "Router log records accepted by a configured sink.",
        &["sink"],
        SelfMetric,
    ),
    family(
        "kcc_log_retries_total",
        Counter,
        "Log sink delivery retries.",
        &["sink"],
        SelfMetric,
    ),
    family(
        "kcc_log_records_dropped_total",
        Counter,
        "Router log records a log sink dropped, by sink and reason.",
        &["sink", "reason"],
        SelfMetric,
    ),
];

/// Looks up a family by name.
#[inline]
#[must_use]
pub fn find(name: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|family| family.name == name)
}
