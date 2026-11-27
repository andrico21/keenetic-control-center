//! Wi-Fi access-point, radio, and station operations.

use alloc::collections::BTreeMap;

use kcc_app::workflow::CliChangeRequest;
use kcc_catalog::Risk;
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    decode, descriptor, interfaces, read_show,
};

/// Tolerant, secret-free Wi-Fi response models.
pub mod models;
/// Catalog validation and protected CLI rendering.
pub mod plan;

/// Wi-Fi access-point view.
pub type AccessPoint = models::AccessPoint;
/// Wi-Fi radio view.
pub type Radio = models::Radio;
/// Associated station view.
pub type Station = models::Station;

/// Wi-Fi encryption selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Encryption {
    /// Enable encryption with firmware defaults.
    Enable,
    /// WPA2 encryption.
    Wpa2,
    /// WPA3 encryption.
    Wpa3,
}

/// Wi-Fi read inventory.
const READS: &[OperationDescriptor] = &[
    descriptor::read("access_point", "show interface"),
    descriptor::read("radios", "show interface"),
    descriptor::read("stations", "show associations"),
];

/// Wi-Fi write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::write("ssid", "interface ssid"),
    descriptor::write("wpa_psk", "interface authentication wpa-psk"),
    descriptor::write("encryption_enable", "interface encryption enable"),
    descriptor::write("encryption_wpa2", "interface encryption wpa2"),
    descriptor::write("encryption_wpa3", "interface encryption wpa3"),
    descriptor::write("hide_ssid", "interface hide-ssid"),
    descriptor::write("up", "interface up"),
    descriptor::write("schedule", "interface schedule"),
    descriptor::write("channel", "interface channel"),
    descriptor::write("channel_width", "interface channel width"),
    descriptor::write("power", "interface power"),
    descriptor::write("country_code", "interface country-code"),
    descriptor::write("band_steering", "interface band-steering"),
];

/// Wi-Fi domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Wifi,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

impl Encryption {
    /// Returns the matching catalog path and CLI suffix.
    const fn command(self) -> (&'static str, &'static str) {
        match self {
            Self::Enable => ("interface encryption enable", "encryption enable"),
            Self::Wpa2 => ("interface encryption wpa2", "encryption wpa2"),
            Self::Wpa3 => ("interface encryption wpa3", "encryption wpa3"),
        }
    }
}

/// Reads one slash-safe access point through root POST.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_access_point(router: &RouterCtx, name: &ObjectName) -> Result<AccessPoint> {
    let value = serde_json::to_value(interfaces::read_interface(router, name).await?)
        .map_err(|_error| DomainError::InvalidResponse)?;
    decode::value(router.client.log_id(), "show interface", &value)
}

/// Reads every access point from `show interface`, each with whether it stores a WPA
/// pre-shared key; the key itself is discarded at the read boundary.
///
/// # Errors
///
/// Returns an error when the router request fails or its reply, an access point included,
/// does not decode ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_access_points(router: &RouterCtx) -> Result<BTreeMap<String, AccessPoint>> {
    let values: BTreeMap<String, Value> = read_show(&router.client, &["show", "interface"]).await?;
    let points = values
        .into_iter()
        .filter(|(_, value)| value.get("type").and_then(Value::as_str) == Some("AccessPoint"))
        .collect();
    decode::value(
        router.client.log_id(),
        "show interface",
        &Value::Object(points),
    )
}

/// Reads radios and derives their bands from `show interface`.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_radios(router: &RouterCtx) -> Result<BTreeMap<String, Radio>> {
    let values: BTreeMap<String, Value> = read_show(&router.client, &["show", "interface"]).await?;
    Ok(values
        .into_iter()
        .filter_map(|(name, value)| {
            let radio = serde_json::from_value::<Radio>(value).ok()?;
            (radio.kind.as_deref() == Some("WifiMaster")).then_some((name, radio))
        })
        .collect())
}

/// Reads associated Wi-Fi stations.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_stations(router: &RouterCtx) -> Result<Vec<Station>> {
    read_show(&router.client, &["show", "associations"]).await
}

/// Plans an access-point SSID change.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_ssid(router: &RouterCtx, name: &ObjectName, ssid: &str) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface ssid",
        &json!({"ssid": ssid}),
        Some(("ssid", Value::String(ssid.to_owned()))),
    )
}

/// Plans a WPA pre-shared key while retaining plaintext only in protected storage; its
/// read-back requires the stored key to differ from the one before the write.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_wpa_psk(router: &RouterCtx, name: &ObjectName, psk: SecretString) -> Result<ChangeOp> {
    plan::plan_secret(router, name, "interface authentication wpa-psk", "psk", psk)
}

/// Plans access-point encryption without handling PSK material.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_encryption(
    router: &RouterCtx,
    name: &ObjectName,
    encryption: Encryption,
) -> Result<ChangeOp> {
    plan::plan(router, name, encryption.command().0, &json!({}), None)
}

/// Plans whether an access point hides its SSID.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_hide_ssid(router: &RouterCtx, name: &ObjectName, hidden: bool) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface hide-ssid",
        &toggle_body(hidden),
        None,
    )
}

/// Plans whether an access point is enabled.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, management classification performs read-only topology requests.
#[inline]
pub async fn plan_up(router: &RouterCtx, name: &ObjectName, enabled: bool) -> Result<ChangeOp> {
    let risk = if enabled {
        Risk::Write
    } else {
        interfaces::detect_management(router, name).await?.risk()
    };
    plan::plan_with_risk(
        router,
        name,
        if enabled {
            "interface up"
        } else {
            "interface down"
        },
        &json!({}),
        Some((
            "state",
            Value::String(if enabled { "up" } else { "down" }.to_owned()),
        )),
        risk,
    )
}

/// Plans an access-point schedule.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, management classification performs read-only topology requests.
#[inline]
pub async fn plan_schedule(
    router: &RouterCtx,
    name: &ObjectName,
    schedule: &str,
) -> Result<ChangeOp> {
    let risk = interfaces::detect_management(router, name).await?.risk();
    plan::plan_with_risk(
        router,
        name,
        "interface schedule",
        &json!({"schedule": schedule}),
        None,
        risk,
    )
}

/// Plans automatic or firmware-defined radio channel selection.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_channel(router: &RouterCtx, name: &ObjectName, channel: &str) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface channel",
        &json!({"channel": channel}),
        None,
    )
}

/// Plans radio channel width.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_channel_width(router: &RouterCtx, name: &ObjectName, width: &str) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface channel width",
        &json!({"width": width}),
        None,
    )
}

/// Plans radio transmit power.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_power(router: &RouterCtx, name: &ObjectName, power: i64) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface power",
        &json!({"power": power}),
        None,
    )
}

/// Plans the radio country code.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_country_code(router: &RouterCtx, name: &ObjectName, code: &str) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface country-code",
        &json!({"code": code}),
        None,
    )
}

/// Plans whether band steering is enabled.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_band_steering(
    router: &RouterCtx,
    name: &ObjectName,
    enabled: bool,
) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface band-steering",
        &toggle_body(enabled),
        None,
    )
}

/// Converts a Wi-Fi plan into a protected parser request.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the plan holds no request, the request is not a
/// Wi-Fi command, lacks a field, or a command cannot be given a read-back of its own (a
/// secret-bearing command, or a line that is not exactly one configuration row), or the key
/// command cannot be bound to its template; [`DomainError::InvalidCliToken`] when an SSID or
/// country code cannot be quoted; and [`DomainError::Workflow`] when a rendered line does not
/// match its request.
#[inline]
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    plan::change_request(name, operation)
}

/// Builds an enabled or `no` request body.
fn toggle_body(enabled: bool) -> Value {
    if enabled {
        json!({})
    } else {
        json!({"no": true})
    }
}
