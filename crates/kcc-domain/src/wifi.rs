//! Wi-Fi access-point, radio, and station operations.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain async reads and planning functions are not useful inline candidates"
)]

use alloc::collections::BTreeMap;

use kcc_app::{permissions::Permission, workflow::CliChangeRequest};
use kcc_catalog::Risk;
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    interfaces, read_show,
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
/// Stored NS3 marker summary.
pub type Ns3Presence = models::Ns3Presence;

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
    read_operation("access_point", "show interface"),
    read_operation("radios", "show interface"),
    read_operation("stations", "show associations"),
];

/// Wi-Fi write inventory.
const WRITES: &[OperationDescriptor] = &[
    write_operation("ssid", "interface ssid"),
    write_operation("wpa_psk", "interface authentication wpa-psk"),
    write_operation("encryption_enable", "interface encryption enable"),
    write_operation("encryption_wpa2", "interface encryption wpa2"),
    write_operation("encryption_wpa3", "interface encryption wpa3"),
    write_operation("hide_ssid", "interface hide-ssid"),
    write_operation("up", "interface up"),
    write_operation("schedule", "interface schedule"),
    write_operation("channel", "interface channel"),
    write_operation("channel_width", "interface channel width"),
    write_operation("power", "interface power"),
    write_operation("country_code", "interface country-code"),
    write_operation("band_steering", "interface band-steering"),
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
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_access_point(router: &RouterCtx, name: &ObjectName) -> Result<AccessPoint> {
    let value = serde_json::to_value(interfaces::read_interface(router, name).await?)
        .map_err(|_error| DomainError::InvalidResponse)?;
    serde_json::from_value(value).map_err(|_error| DomainError::InvalidResponse)
}

/// Reads radios and derives their bands from `show interface`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
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
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_stations(router: &RouterCtx) -> Result<Vec<Station>> {
    read_show(&router.client, &["show", "associations"]).await
}

/// Checks only NS3 presence and plausible encoded length, without decoding it.
#[must_use]
pub fn ns3_presence(blob: Option<&str>) -> Ns3Presence {
    let length = blob.map(str::len);
    Ns3Presence::new(
        blob.is_some(),
        length,
        length.is_some_and(|value| value >= 24 && value.is_multiple_of(4)),
    )
}

/// Plans an access-point SSID change.
pub fn plan_ssid(router: &RouterCtx, name: &ObjectName, ssid: &str) -> Result<ChangeOp> {
    plan::plan(
        router,
        name,
        "interface ssid",
        &json!({"ssid": ssid}),
        Some(("ssid", Value::String(ssid.to_owned()))),
    )
}

/// Plans a WPA pre-shared key while retaining plaintext only in protected storage.
pub fn plan_wpa_psk(router: &RouterCtx, name: &ObjectName, psk: SecretString) -> Result<ChangeOp> {
    plan::plan_secret(router, name, "interface authentication wpa-psk", "psk", psk)
}

/// Plans access-point encryption without handling PSK material.
pub fn plan_encryption(
    router: &RouterCtx,
    name: &ObjectName,
    encryption: Encryption,
) -> Result<ChangeOp> {
    plan::plan(router, name, encryption.command().0, &json!({}), None)
}

/// Plans whether an access point hides its SSID.
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
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_up(router: &RouterCtx, name: &ObjectName, enabled: bool) -> Result<ChangeOp> {
    let risk = if enabled {
        Risk::Write
    } else {
        interfaces::detect_management(router, name)
            .await?
            .risk(name)
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
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_schedule(
    router: &RouterCtx,
    name: &ObjectName,
    schedule: &str,
) -> Result<ChangeOp> {
    let risk = interfaces::detect_management(router, name)
        .await?
        .risk(name);
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
pub fn change_request(name: &ObjectName, operation: &ChangeOp) -> Result<CliChangeRequest> {
    plan::change_request(name, operation)
}

/// Builds a read descriptor.
const fn read_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    }
}

/// Builds a write descriptor.
const fn write_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}

/// Builds an enabled or `no` request body.
fn toggle_body(enabled: bool) -> Value {
    if enabled {
        json!({})
    } else {
        json!({"no": true})
    }
}
