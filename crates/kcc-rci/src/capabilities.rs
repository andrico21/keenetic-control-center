//! Router identity, firmware, component, rights, and inventory detection.

use alloc::collections::{BTreeMap, BTreeSet};

use reqwest::{StatusCode, header};
use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::{Map, Value};

use crate::{
    RciError, RciResponse, RouterUrl,
    auth::{Scheme, WwwAuthenticate},
    engine,
    session::Manager,
    version::FirmwareVersion,
};

/// Firmware lines exercised by the live hardware suites.
///
/// A line is added only after the live suites pass on it, recorded in
/// `docs/FIRMWARE.md`.
pub const HARDWARE_VERIFIED: &[(u16, u16)] = &[(5, 1)];

/// The oldest documented firmware line.
const OLDEST_DOCUMENTED: (u16, u16) = (4, 3);

/// Netcraze hardware ids mapped to the nearest Keenetic hardware family for catalog fallback.
///
/// UNVERIFIED: no Netcraze hardware has been tested; the mapping follows the shared model
/// numbering and the nearest Keenetic id present in `catalog/sources.toml`.
pub const NETCRAZE_ALIASES: &[(&str, &str)] = &[
    ("NC-1812", "KN-1812"),
    ("NC-2312", "KN-2311"),
    ("NC-3013", "KN-3010"),
    ("NC-3611", "KN-3610"),
    ("NC-4210", "KN-4110"),
];

/// The router brand.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Brand {
    /// Keenetic hardware.
    Keenetic,
    /// Netcraze hardware.
    Netcraze,
    /// Any other or missing vendor.
    Unknown,
}

impl Brand {
    /// Classifies a `vendor` or `manufacturer` value.
    fn classify(value: &str) -> Option<Self> {
        let lower = value.to_ascii_lowercase();
        if lower.contains("netcraze") {
            Some(Self::Netcraze)
        } else if lower.contains("keenetic") {
            Some(Self::Keenetic)
        } else {
            None
        }
    }
}

/// How well a firmware line is supported.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SupportTier {
    /// Below 4.3, or the firmware version is unknown.
    Unsupported,
    /// Supported from the official documentation only.
    DocumentationBased,
    /// Exercised by the live hardware suites.
    HardwareVerified,
}

/// The router operating mode reported by `show system mode`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SystemMode {
    /// Router mode.
    Router,
    /// Extender (mesh) mode.
    Extender,
    /// Access point mode.
    Ap,
    /// Repeater (Wi-Fi client bridge) mode.
    Repeater,
    /// A mode this version does not know.
    Other(String),
}

impl SystemMode {
    /// Maps a reported mode name.
    fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "router" => Self::Router,
            "extender" => Self::Extender,
            "ap" | "access-point" => Self::Ap,
            "repeater" => Self::Repeater,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// An authentication scheme advertised by `/auth`, without its per-session parameters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum AuthSchemeKind {
    /// `x-ndw2-interactive`.
    Ndw2,
    /// `x-ndw4-interactive`.
    Ndw4,
    /// Another scheme token.
    Other(String),
}

/// The `ndw` member of `show version`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct NdwInfo {
    /// Comma-separated installed components.
    #[serde(default, deserialize_with = "text")]
    pub components: Option<String>,
    /// Comma-separated hardware features.
    #[serde(default, deserialize_with = "text")]
    pub features: Option<String>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `show version` response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ShowVersion {
    /// Release string, e.g. `5.01.C.3.0-0`.
    #[serde(default, deserialize_with = "text")]
    pub release: Option<String>,
    /// Title, e.g. `5.1.3` or `5.2 Beta 1`.
    #[serde(default, deserialize_with = "text")]
    pub title: Option<String>,
    /// Update channel, e.g. `stable`.
    #[serde(default, deserialize_with = "text")]
    pub sandbox: Option<String>,
    /// CPU architecture.
    #[serde(default, deserialize_with = "text")]
    pub arch: Option<String>,
    /// Hardware id, e.g. `KN-1811`.
    #[serde(default, deserialize_with = "text")]
    pub hw_id: Option<String>,
    /// Marketing model name.
    #[serde(default, deserialize_with = "text")]
    pub model: Option<String>,
    /// Device name.
    #[serde(default, deserialize_with = "text")]
    pub device: Option<String>,
    /// Vendor name.
    #[serde(default, deserialize_with = "text")]
    pub vendor: Option<String>,
    /// Manufacturer name.
    #[serde(default, deserialize_with = "text")]
    pub manufacturer: Option<String>,
    /// Firmware region.
    #[serde(default, deserialize_with = "text")]
    pub region: Option<String>,
    /// Components and features.
    #[serde(default)]
    pub ndw: Option<NdwInfo>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `show identification` response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct Identification {
    /// Serial number.
    #[serde(default, deserialize_with = "text")]
    pub serial: Option<String>,
    /// Service tag.
    #[serde(default, deserialize_with = "text")]
    pub servicetag: Option<String>,
    /// Hardware id.
    #[serde(default, deserialize_with = "text")]
    pub hwid: Option<String>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `whoami` response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct WhoAmI {
    /// Current account name.
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    /// Account permission tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `show system mode` response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ShowSystemMode {
    /// The mode in effect.
    #[serde(default, deserialize_with = "text")]
    pub active: Option<String>,
    /// The mode selected for the next boot.
    #[serde(default, deserialize_with = "text")]
    pub selected: Option<String>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One entry of the `show interface` response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ShowInterface {
    /// Interface id.
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    /// Interface type, e.g. `Port`, `WifiMaster`.
    #[serde(default, rename = "type", deserialize_with = "text")]
    pub kind: Option<String>,
    /// Port label printed on the case.
    #[serde(default, deserialize_with = "text")]
    pub label: Option<String>,
    /// Fields this version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Rights derived from the `whoami` tags.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag mirrors one independent router permission tag"
)]
pub struct RouterRights {
    /// `cli`: command-line and RCI access.
    pub cli: bool,
    /// `http`: web interface access.
    pub http: bool,
    /// `readonly`: read-only access.
    pub readonly: bool,
    /// `manager`: management access.
    pub manager: bool,
    /// `http-proxy`: HTTP proxy access.
    pub http_proxy: bool,
    /// Tags without a dedicated flag.
    pub other: BTreeSet<String>,
}

impl RouterRights {
    /// Maps router permission tags.
    #[inline]
    #[must_use]
    pub fn from_tags<I, S>(tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rights = Self::default();
        for tag in tags {
            match tag.as_ref() {
                "cli" => rights.cli = true,
                "http" => rights.http = true,
                "readonly" => rights.readonly = true,
                "manager" => rights.manager = true,
                "http-proxy" => rights.http_proxy = true,
                other => {
                    let _inserted: bool = rights.other.insert(other.to_owned());
                }
            }
        }
        rights
    }
}

/// A physical switch port.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PortInfo {
    /// Interface id, e.g. `GigabitEthernet0/1`.
    pub id: String,
    /// Case label, when reported.
    pub label: Option<String>,
}

/// A Wi-Fi radio.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RadioInfo {
    /// Radio interface id, e.g. `WifiMaster0`.
    pub id: String,
    /// Bands from `show interface bands`, when available.
    pub bands: Option<Vec<String>>,
}

/// Interface inventory summary.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct InterfaceInventory {
    /// Physical ports in router order.
    pub ports: Vec<PortInfo>,
    /// Wi-Fi radios ordered by id.
    pub radios: Vec<RadioInfo>,
    /// Raw `show interface bands` response; `None` when the path is absent.
    pub bands: Option<Value>,
}

/// Router identity and capabilities.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct RouterInfo {
    /// The `show version` response.
    pub version: ShowVersion,
    /// Parsed firmware version (title first, then release).
    pub firmware: Option<FirmwareVersion>,
    /// Brand from `vendor`, then `manufacturer`.
    pub brand: Brand,
    /// Installed components.
    pub components: BTreeSet<String>,
    /// Hardware features.
    pub features: BTreeSet<String>,
    /// Authentication schemes advertised by `/auth`, in router preference order.
    pub auth_schemes: Vec<AuthSchemeKind>,
    /// The `whoami` response; `None` when absent.
    pub user: Option<WhoAmI>,
    /// Rights of the current user; `None` when `whoami` is absent.
    pub rights: Option<RouterRights>,
    /// Operating mode; `None` when `show system mode` is absent.
    pub system_mode: Option<SystemMode>,
    /// Interface inventory; `None` when `show interface` is absent.
    pub interfaces: Option<InterfaceInventory>,
    /// The `show identification` response; `None` when absent.
    pub identification: Option<Identification>,
}

impl RouterInfo {
    /// Detects identity and capabilities through an authenticated session.
    ///
    /// `router` must equal the origin bound to `client`; other origins are refused before
    /// the `/auth` scheme probe. Only `show version` is required: any other path answered 404,
    /// 405, or with an RCI error status is recorded as `None`.
    ///
    /// # Errors
    ///
    /// Returns transport, authentication, HTTP, decode, or body-size failures, and
    /// [`RciError::NotFound`] when `show version` is absent.
    // cancel-safe: every request is a read.
    #[inline]
    pub async fn detect(client: &Manager, router: &RouterUrl) -> Result<Self, RciError> {
        Self::detect_capped(client, router, engine::DEFAULT_RESPONSE_BYTES).await
    }

    /// Detects identity and capabilities, reading at most `cap` bytes per response.
    ///
    /// # Errors
    ///
    /// As [`RouterInfo::detect`].
    // cancel-safe: every request is a read.
    pub(crate) async fn detect_capped(
        client: &Manager,
        router: &RouterUrl,
        cap: usize,
    ) -> Result<Self, RciError> {
        let read = |path| read_optional(client, path, cap);
        let auth_schemes = probe_auth_schemes(client, router).await?;
        let version: ShowVersion =
            decode(read("/rci/show/version").await?.ok_or(RciError::NotFound)?)?;
        let identification = read("/rci/show/identification")
            .await?
            .map(decode::<Identification>)
            .transpose()?;
        let user = read("/rci/whoami")
            .await?
            .map(decode::<WhoAmI>)
            .transpose()?;
        let system_mode = read("/rci/show/system/mode")
            .await?
            .map(decode::<ShowSystemMode>)
            .transpose()?
            .and_then(|mode| mode.active.or(mode.selected))
            .map(|name| SystemMode::from_name(&name));
        let interfaces = match read("/rci/show/interface").await? {
            None => None,
            Some(value) => {
                let bands = read("/rci/show/interface/bands").await?;
                Some(inventory(value, bands)?)
            }
        };
        Ok(Self::assemble(
            version,
            auth_schemes,
            user,
            system_mode,
            interfaces,
            identification,
        ))
    }

    /// Builds the detected information from decoded responses.
    fn assemble(
        version: ShowVersion,
        auth_schemes: Vec<AuthSchemeKind>,
        user: Option<WhoAmI>,
        system_mode: Option<SystemMode>,
        interfaces: Option<InterfaceInventory>,
        identification: Option<Identification>,
    ) -> Self {
        let firmware = version
            .title
            .as_deref()
            .and_then(|title| FirmwareVersion::from_title(title).ok())
            .or_else(|| FirmwareVersion::from_release(version.release.as_deref()?).ok());
        let brand = [version.vendor.as_deref(), version.manufacturer.as_deref()]
            .into_iter()
            .flatten()
            .find_map(Brand::classify)
            .unwrap_or(Brand::Unknown);
        let ndw = version.ndw.as_ref();
        let components = comma_set(ndw.and_then(|info| info.components.as_deref()));
        let features = comma_set(ndw.and_then(|info| info.features.as_deref()));
        let rights = user
            .as_ref()
            .map(|whoami| RouterRights::from_tags(&whoami.tags));
        Self {
            version,
            firmware,
            brand,
            components,
            features,
            auth_schemes,
            user,
            rights,
            system_mode,
            interfaces,
            identification,
        }
    }

    /// Returns the support tier of the detected firmware line.
    #[inline]
    #[must_use]
    pub fn support_tier(&self) -> SupportTier {
        self.firmware.map_or(SupportTier::Unsupported, |firmware| {
            tier_for(firmware.line())
        })
    }

    /// Returns the serial number from `show identification`.
    #[inline]
    #[must_use]
    pub fn serial(&self) -> Option<&str> {
        self.identification.as_ref()?.serial.as_deref()
    }

    /// Returns the hardware id from `show version`.
    #[inline]
    #[must_use]
    pub fn hw_id(&self) -> Option<&str> {
        self.version.hw_id.as_deref()
    }

    /// Returns the Keenetic hardware id whose catalog applies to this router.
    ///
    /// Keenetic ids map to themselves; Netcraze ids go through [`NETCRAZE_ALIASES`]
    /// (UNVERIFIED).
    #[inline]
    #[must_use]
    pub fn catalog_hw_id(&self) -> Option<&str> {
        self.hw_id().and_then(keenetic_family)
    }
}

/// Returns the support tier of a `(major, minor)` firmware line.
#[inline]
#[must_use]
pub fn tier_for(line: (u16, u16)) -> SupportTier {
    if HARDWARE_VERIFIED.contains(&line) {
        SupportTier::HardwareVerified
    } else if line >= OLDEST_DOCUMENTED {
        SupportTier::DocumentationBased
    } else {
        SupportTier::Unsupported
    }
}

/// Maps a hardware id to the Keenetic hardware family used for catalog lookup.
///
/// Netcraze mappings are UNVERIFIED until Netcraze hardware is tested.
#[inline]
#[must_use]
pub fn keenetic_family(hw_id: &str) -> Option<&str> {
    if hw_id.starts_with("KN-") {
        return Some(hw_id);
    }
    NETCRAZE_ALIASES
        .iter()
        .find(|(netcraze, _keenetic)| netcraze.eq_ignore_ascii_case(hw_id))
        .map(|(_netcraze, keenetic)| *keenetic)
}

/// Reads the schemes advertised by an unauthenticated `GET /auth`.
///
/// # Errors
///
/// Returns transport or timeout failures.
// cancel-safe: the probe is a read.
async fn probe_auth_schemes(
    client: &Manager,
    router: &RouterUrl,
) -> Result<Vec<AuthSchemeKind>, RciError> {
    let response = client.probe_auth(router).await?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(Vec::new());
    }
    let mut schemes = Vec::new();
    let parsed = response
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| WwwAuthenticate::parse(value).ok());
    for authenticate in parsed {
        for scheme in authenticate.schemes() {
            let kind = match scheme {
                Scheme::Ndw2(_challenge) => AuthSchemeKind::Ndw2,
                Scheme::Ndw4(_challenge) => AuthSchemeKind::Ndw4,
                Scheme::Unknown(opaque) => AuthSchemeKind::Other(opaque.name.to_ascii_lowercase()),
            };
            if !schemes.contains(&kind) {
                schemes.push(kind);
            }
        }
    }
    Ok(schemes)
}

/// Reads a JSON resource, returning `None` for 404, 405, or an RCI error status.
///
/// # Errors
///
/// Returns transport, authentication, other HTTP status, decode, or body-size failures.
// cancel-safe: the request is a read.
async fn read_optional(
    client: &Manager,
    path: &str,
    cap: usize,
) -> Result<Option<Value>, RciError> {
    let response = client.get(path).await?;
    let status = response.status();
    if matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(RciError::Http {
            status: status.as_u16(),
        });
    }
    let body = engine::body::read_capped(response, cap).await?;
    let value = serde_json::from_slice::<Value>(&body).map_err(|_error| RciError::Decode)?;
    match RciResponse::from_value(value) {
        Ok(decoded) => Ok(Some(decoded.value)),
        Err(RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message: _,
        }) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Decodes a typed model.
///
/// # Errors
///
/// Returns [`RciError::Decode`] when the value has the wrong shape.
fn decode<T>(value: Value) -> Result<T, RciError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|_error| RciError::Decode)
}

/// Builds the interface inventory from `show interface` and `show interface bands`.
///
/// # Errors
///
/// Returns [`RciError::Decode`] when `show interface` is not an object of entries.
fn inventory(interfaces: Value, bands: Option<Value>) -> Result<InterfaceInventory, RciError> {
    let entries: BTreeMap<String, ShowInterface> = decode(interfaces)?;
    let mut ordered = entries.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(_key, entry)| {
        entry
            .extra
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
    });
    let mut ports = Vec::new();
    let mut radio_ids = BTreeSet::new();
    for (key, entry) in ordered {
        let id = entry.id.clone().unwrap_or(key);
        match entry.kind.as_deref() {
            Some("Port") => ports.push(PortInfo {
                id,
                label: entry.label,
            }),
            Some("WifiMaster") => {
                let _inserted: bool = radio_ids.insert(id);
            }
            _ => {
                if let Some((radio, _rest)) = id.split_once('/')
                    && radio.starts_with("WifiMaster")
                {
                    let _inserted: bool = radio_ids.insert(radio.to_owned());
                }
            }
        }
    }
    let radios = radio_ids
        .into_iter()
        .map(|id| RadioInfo {
            bands: bands
                .as_ref()
                .and_then(|value| value.get(&id))
                .and_then(band_list),
            id,
        })
        .collect();
    Ok(InterfaceInventory {
        ports,
        radios,
        bands,
    })
}

/// Reads one radio's bands from a string or an array of strings.
fn band_list(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(band) => Some(vec![band.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => None,
    }
}

/// Splits a comma-separated list into a set of trimmed, non-empty names.
fn comma_set(list: Option<&str>) -> BTreeSet<String> {
    list.into_iter()
        .flat_map(|text| text.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Deserializes an optional text field that routers may send as a string or a number.
///
/// # Errors
///
/// Returns a deserialization error for arrays and objects.
fn text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Number(value)) => Ok(Some(value.to_string())),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => {
            Err(D::Error::custom("expected a string or a number"))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Brand, InterfaceInventory, RouterInfo, RouterRights, ShowVersion, SupportTier, inventory,
        keenetic_family, tier_for,
    };

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    #[expect(clippy::unwrap_used, reason = "valid fixtures must parse in this test")]
    fn tolerant_models_and_mappings() {
        let version: ShowVersion = serde_json::from_value(json!({
            "title": "5.2 Beta 1", "release": 5_i32, "vendor": "Netcraze", "future": [1_i32]
        }))
        .unwrap();
        assert_eq!(version.release.as_deref(), Some("5"));
        assert!(version.extra.contains_key("future"));
        let info = RouterInfo::assemble(version, Vec::new(), None, None, None, None);
        assert_eq!(info.brand, Brand::Netcraze);
        assert_eq!(info.support_tier(), SupportTier::DocumentationBased);
        assert_eq!(tier_for((5, 1)), SupportTier::HardwareVerified);
        assert_eq!(tier_for((4, 2)), SupportTier::Unsupported);
        assert_eq!(keenetic_family("nc-3013"), Some("KN-3010"));
        assert_eq!(keenetic_family("KN-1811"), Some("KN-1811"));
        assert_eq!(keenetic_family("XX-1"), None);

        let rights = RouterRights::from_tags(["cli", "readonly", "opt"]);
        assert!(rights.cli && rights.readonly && !rights.http);
        assert!(rights.other.contains("opt"));

        let InterfaceInventory {
            ports,
            radios,
            bands: _,
        } = inventory(
            json!({
                "GigabitEthernet0/1": {"type": "Port", "index": 1_i32, "label": 2_i32},
                "GigabitEthernet0/0": {"type": "Port", "index": 0_i32, "label": "1"},
                "WifiMaster1": {"id": "WifiMaster1", "type": "WifiMaster"},
                "WifiMaster0/AccessPoint0": {"type": "AccessPoint"}
            }),
            Some(json!({"WifiMaster0": "2.4", "WifiMaster1": ["5"]})),
        )
        .unwrap();
        assert_eq!(
            ports
                .iter()
                .map(|port| (port.id.as_str(), port.label.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("GigabitEthernet0/0", Some("1")),
                ("GigabitEthernet0/1", Some("2"))
            ]
        );
        assert_eq!(
            radios
                .iter()
                .map(|radio| (radio.id.as_str(), radio.bands.clone()))
                .collect::<Vec<_>>(),
            [
                ("WifiMaster0", Some(vec!["2.4".to_owned()])),
                ("WifiMaster1", Some(vec!["5".to_owned()]))
            ]
        );
    }
}
