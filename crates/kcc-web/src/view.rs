//! Display models of routers: registry entries and live feed state, formatted in the page
//! locale and reduced to what the fleet cards and the dashboard show.

use kcc_app::{
    permissions::{Permission, Role},
    poller::Snapshot,
    registry::{ProfileSource, RegistryEntry},
};
use kcc_i18n::{bundle::MessageKey, format, keys, locale::Locale};
use kcc_rci::capabilities::{Brand, RouterInfo, SupportTier};
use serde_json::Value;

use crate::{
    gauge::{Gauge, memory},
    network::{
        AccessPointRow, RadioRow, WanRow, access_points, access_points_table, internet, radios,
        wan_rows, wan_table,
    },
    page::RouterStatus,
    page_kit::gate::Controls,
    table::view::TableView,
    telemetry::FeedState,
    traffic::number,
};

/// What the Web UI shows about one router.
#[derive(Debug, Clone)]
pub(crate) struct RouterView {
    /// Profile id.
    id: String,
    /// Reachability pill; unknown until the first poll.
    status: RouterStatus,
    /// Where the profile is defined.
    source: ProfileSource,
    /// What the viewer may do on the router.
    controls: Controls,
    /// Brand wordmark.
    brand: Option<MessageKey>,
    /// Model name.
    model: Option<String>,
    /// Hardware id, such as `KN-1811`.
    hw_id: Option<String>,
    /// Firmware version.
    firmware: Option<String>,
    /// Serial number.
    serial: Option<String>,
    /// Support notice of a firmware line that is not hardware-verified.
    tier: Option<MessageKey>,
    /// Host name.
    hostname: Option<String>,
    /// Uptime.
    uptime: Option<String>,
    /// CPU load.
    cpu: Option<Gauge>,
    /// Memory use.
    memory: Option<Gauge>,
    /// Internet state.
    internet: MessageKey,
    /// Clients online, formatted.
    clients: Option<String>,
    /// WAN connections.
    wan: Vec<WanRow>,
    /// Radios.
    radios: Vec<RadioRow>,
    /// Access points.
    access_points: Vec<AccessPointRow>,
    /// Whether running configuration differs from startup.
    unsaved: bool,
    /// Whether any poll has reached the router, so the facts below are known.
    observed: bool,
    /// Latest download and upload rates.
    traffic: Option<(String, String)>,
}

impl RouterView {
    /// The view of `entry` with the live `state`, formatted in `locale`, with no controls.
    pub(crate) fn new(entry: &RegistryEntry, state: &FeedState, locale: Locale) -> Self {
        let status = match (state.polled(), state.reachable()) {
            (false, _) => RouterStatus::Unknown,
            (true, true) => RouterStatus::Online,
            (true, false) => RouterStatus::Offline,
        };
        let mut view = Self {
            id: entry.profile.id.clone(),
            status,
            source: entry.source,
            controls: Controls::default(),
            brand: None,
            model: None,
            hw_id: None,
            firmware: None,
            serial: None,
            tier: None,
            hostname: None,
            uptime: None,
            cpu: None,
            memory: None,
            internet: keys::WEB_INTERNET_UNKNOWN,
            clients: None,
            wan: Vec::new(),
            radios: Vec::new(),
            access_points: Vec::new(),
            unsaved: false,
            observed: state.snapshot().is_some(),
            traffic: state.point().map(|point| {
                (
                    format::bit_rate(locale, point.rx()),
                    format::bit_rate(locale, point.tx()),
                )
            }),
        };
        if let Some(snapshot) = state.snapshot() {
            view.fill(snapshot, locale);
        }
        view
    }

    /// Enables the controls `role` may use on this router.
    #[must_use]
    pub(crate) fn allow(mut self, role: &Role) -> Self {
        self.controls = Controls::new(role, &self.id);
        self
    }

    /// Copies the identity, health and network facts of `snapshot`.
    fn fill(&mut self, snapshot: &Snapshot, locale: Locale) {
        let info = &snapshot.info;
        self.brand = brand(info);
        self.model = info
            .version
            .device
            .clone()
            .filter(|_| self.brand.is_some())
            .or_else(|| info.version.model.clone());
        self.hw_id = info.hw_id().map(str::to_owned);
        self.firmware = info
            .firmware
            .map(|firmware| firmware.to_string())
            .or_else(|| info.version.title.clone().filter(|title| !title.is_empty()));
        self.serial = info.serial().map(str::to_owned);
        self.tier = tier(info);
        let system = &snapshot.system;
        self.hostname = system
            .get("hostname")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.uptime = system
            .get("uptime")
            .and_then(number)
            .map(|seconds| format::duration(locale, seconds));
        self.cpu = system
            .get("cpuload")
            .and_then(number)
            .map(|load| Gauge::cpu(load, locale));
        self.memory = memory(system, locale);
        self.internet = internet(snapshot);
        self.clients = Some(format::integer(locale, snapshot.clients_count));
        self.wan = wan_rows(&snapshot.interfaces_summary);
        self.radios = radios(info);
        self.access_points = access_points(&snapshot.interfaces_summary);
        self.unsaved = snapshot.last_change.get("unsaved").and_then(Value::as_bool) == Some(true);
    }

    /// Profile id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Reachability pill.
    pub(crate) const fn status(&self) -> RouterStatus {
        self.status
    }

    /// Whether a poll has completed.
    pub(crate) const fn polled(&self) -> bool {
        !matches!(self.status, RouterStatus::Unknown)
    }

    /// Whether `kcc.toml` defines the profile.
    pub(crate) const fn config_defined(&self) -> bool {
        matches!(self.source, ProfileSource::Config)
    }

    /// Whether the viewer may edit the profile: a Web UI profile and `ManageRouters`.
    pub(crate) fn can_edit(&self) -> bool {
        !self.config_defined() && self.controls.holds(Permission::ManageRouters)
    }

    /// Whether the viewer may save the router configuration.
    pub(crate) fn can_save(&self) -> bool {
        self.controls.holds(Permission::Save)
    }

    /// Brand wordmark.
    pub(crate) const fn brand(&self) -> Option<MessageKey> {
        self.brand
    }

    /// Model name.
    pub(crate) fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Hardware id.
    pub(crate) fn hw_id(&self) -> Option<&str> {
        self.hw_id.as_deref()
    }

    /// Firmware version.
    pub(crate) fn firmware(&self) -> Option<&str> {
        self.firmware.as_deref()
    }

    /// Serial number.
    pub(crate) fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Support notice title of a firmware line that is not hardware-verified.
    pub(crate) const fn tier(&self) -> Option<MessageKey> {
        self.tier
    }

    /// Host name.
    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Uptime.
    pub(crate) fn uptime(&self) -> Option<&str> {
        self.uptime.as_deref()
    }

    /// CPU load.
    pub(crate) const fn cpu(&self) -> Option<&Gauge> {
        self.cpu.as_ref()
    }

    /// Memory use.
    pub(crate) const fn memory(&self) -> Option<&Gauge> {
        self.memory.as_ref()
    }

    /// Internet state.
    pub(crate) const fn internet(&self) -> MessageKey {
        self.internet
    }

    /// Clients online, formatted.
    pub(crate) fn clients(&self) -> Option<&str> {
        self.clients.as_deref()
    }

    /// WAN connections.
    pub(crate) fn wan(&self) -> &[WanRow] {
        &self.wan
    }

    /// Radios.
    pub(crate) fn radios(&self) -> &[RadioRow] {
        &self.radios
    }

    /// Access points.
    pub(crate) fn access_points(&self) -> &[AccessPointRow] {
        &self.access_points
    }

    /// The table of the WAN connections in `locale`.
    pub(crate) fn wan_table(&self, locale: Locale) -> TableView {
        wan_table(&self.wan, locale)
    }

    /// The table of the access points in `locale`.
    pub(crate) fn access_points_table(&self, locale: Locale) -> TableView {
        access_points_table(&self.access_points, locale)
    }

    /// Whether running configuration differs from startup.
    pub(crate) const fn unsaved(&self) -> bool {
        self.unsaved
    }

    /// Whether any poll has reached the router.
    pub(crate) const fn observed(&self) -> bool {
        self.observed
    }

    /// Latest download and upload rates.
    pub(crate) fn traffic(&self) -> Option<(&str, &str)> {
        self.traffic
            .as_ref()
            .map(|(rx, tx)| (rx.as_str(), tx.as_str()))
    }
}

/// The brand wordmark of a detected router.
const fn brand(info: &RouterInfo) -> Option<MessageKey> {
    match info.brand {
        Brand::Keenetic => Some(keys::WEB_BRAND_KEENETIC),
        Brand::Netcraze => Some(keys::WEB_BRAND_NETCRAZE),
        Brand::Unknown | _ => None,
    }
}

/// The notice title for a firmware line that is not hardware-verified.
fn tier(info: &RouterInfo) -> Option<MessageKey> {
    match info.support_tier() {
        SupportTier::DocumentationBased => Some(keys::WEB_TIER_DOCUMENTATION),
        SupportTier::Unsupported => Some(keys::WEB_TIER_UNSUPPORTED),
        SupportTier::HardwareVerified | _ => None,
    }
}
