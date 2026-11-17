//! Read-only target inventory collection and firmware compatibility checks.

use alloc::{collections::BTreeSet, sync::Arc};
use core::{fmt, str, str::FromStr as _};

use kcc_catalog::{Catalog, CatalogError};
use kcc_config::config_text::{Ast, ParseError, Token, parse};
use kcc_rci::{
    ConfigKind, RciBody, RciClient, RciError, RciPath, RouterUrl,
    capabilities::{RouterInfo, SystemMode},
    version::{FirmwareVersion, FirmwareVersionError},
};
use reqwest::header;
use serde_json::Value;
use thiserror::Error;

use crate::management;

/// Authenticated read-only client used while preparing a migration target.
#[expect(
    clippy::module_name_repetitions,
    reason = "the public migration API is explicitly named InventoryClient"
)]
pub struct InventoryClient {
    /// Router origin retained for identity and realm probes.
    router: RouterUrl,
    /// Bounded request engine used for config and optional show reads.
    rci: Arc<RciClient>,
}

impl fmt::Debug for InventoryClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryClient")
            .field("router", &self.router)
            .finish_non_exhaustive()
    }
}

impl InventoryClient {
    /// Shares an existing policy-checked client and its authenticated session for inventory.
    #[inline]
    #[must_use]
    pub fn from_client(client: &Arc<RciClient>) -> Self {
        Self {
            router: client.router_url().clone(),
            rci: Arc::clone(client),
        }
    }
}

/// Physical port role used by migration proposals.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortRole {
    /// Internet uplink.
    Wan,
    /// Numbered local-network port.
    Lan(u16),
    /// SFP cage.
    Sfp,
    /// DSL line.
    Dsl,
    /// A role not recognized by this version.
    Other(String),
}

/// One physical target port with a human case label.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PhysicalPort {
    /// Router interface id.
    pub id: String,
    /// Printed or inferred label.
    pub label: String,
    /// Migration role.
    pub role: PortRole,
}

/// Wi-Fi frequency band.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum RadioBand {
    /// 2.4 GHz.
    Ghz2_4,
    /// 5 GHz.
    Ghz5,
    /// 6 GHz.
    Ghz6,
}

/// One physical Wi-Fi radio.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Radio {
    /// Radio interface id.
    pub id: String,
    /// Supported bands.
    pub bands: BTreeSet<RadioBand>,
}

/// One logical interface relevant to migration mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LogicalInterface {
    /// Interface object name.
    pub name: String,
    /// Interface type inferred from its name.
    pub kind: String,
    /// Whether this interface comes from the target's running defaults.
    pub target_default: bool,
}

/// EULA and initial setup observations.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct InitialSetupState {
    /// Raw `show eula list` response when present.
    pub eula: Option<Value>,
    /// Raw `easyconfig status` response when present.
    pub easyconfig: Option<Value>,
}

/// Complete read-only migration target inventory.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the plan names the public aggregate TargetInventory"
)]
pub struct TargetInventory {
    /// Detected target identity and capabilities.
    pub info: RouterInfo,
    /// Firmware/model-specific catalog view.
    pub catalog: Catalog,
    /// Parsed active configuration.
    pub running_config: Ast,
    /// MD5 advertised by the target startup configuration.
    pub startup_config_md5: Option<String>,
    /// Stable checksum of the target's observed last-change marker.
    pub last_change_checksum: String,
    /// Interface whose address is the one kcc connects to, or `None` when no interface
    /// reported by `show interface` holds it.
    pub management_interface: Option<String>,
    /// Origin used for the current management connection.
    pub management_url: String,
    /// Router account kcc signs in with; a change of its password is a management line.
    pub login: String,
    /// Physical ports and roles.
    pub ports: Vec<PhysicalPort>,
    /// Wi-Fi radios and bands.
    pub radios: Vec<Radio>,
    /// USB modem interfaces.
    pub usb_modems: Vec<String>,
    /// Installed components.
    pub installed_components: BTreeSet<String>,
    /// Components reported as available to install.
    pub available_components: BTreeSet<String>,
    /// Operating mode.
    pub system_mode: Option<SystemMode>,
    /// Whether fail-safe migration can be used.
    pub fail_safe_available: bool,
    /// Authentication realm.
    pub realm: Option<String>,
    /// EULA and initial-setup state.
    pub initial_setup: InitialSetupState,
    /// Logical interfaces in the running configuration.
    pub interfaces: Vec<LogicalInterface>,
    /// Interface ids reported by `show interface`, or `None` when unavailable.
    pub interface_inventory: Option<BTreeSet<String>>,
}

impl TargetInventory {
    /// Collects a read-only target inventory and enforces source/target firmware ordering.
    ///
    /// `source_firmware` must be explicit when the source header and live version are unknown.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::SourceVersionRequired`] for an unknown source version,
    /// [`InventoryError::UnsupportedFirmware`] below 4.3, or
    /// [`InventoryError::TargetFirmwareOlder`] when the target is older than the source.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, every router operation is a read.
    #[inline]
    pub async fn collect(
        client: &InventoryClient,
        source_firmware: Option<FirmwareVersion>,
    ) -> Result<Self, InventoryError> {
        let required_source = source_firmware.ok_or(InventoryError::SourceVersionRequired)?;
        let info = client.rci.detect().await?;
        let target_firmware = info.firmware.ok_or(InventoryError::UnsupportedFirmware)?;
        if target_firmware.line() < (4, 3) {
            return Err(InventoryError::UnsupportedFirmware);
        }
        if target_firmware < required_source {
            return Err(InventoryError::TargetFirmwareOlder {
                source_version: required_source,
                target_version: target_firmware,
            });
        }
        let catalog = Catalog::for_router(&info).map_err(|error| match error {
            CatalogError::UnsupportedFirmware => InventoryError::UnsupportedFirmware,
            CatalogError::InvalidGeneratedCatalog | _ => InventoryError::Catalog,
        })?;
        let bytes = client.rci.download_config(ConfigKind::Running).await?;
        let text = str::from_utf8(secrecy::ExposeSecret::expose_secret(&bytes))
            .map_err(|_error| InventoryError::ConfigEncoding)?;
        let running_config = parse(text)?;
        let startup_bytes = client.rci.download_config(ConfigKind::Startup).await?;
        let startup_text = str::from_utf8(secrecy::ExposeSecret::expose_secret(&startup_bytes))
            .map_err(|_error| InventoryError::ConfigEncoding)?;
        let startup_config = parse(startup_text)?;
        let ports = collect_ports(&info);
        let radios = collect_radios(&info);
        let (usb_modems, interfaces) = collect_interfaces(&running_config);
        let interface_inventory = optional_show(&client.rci, ["interface"])
            .await?
            .and_then(|value| interface_names(&value));
        let management_interface = optional_show(&client.rci, ["show", "interface"])
            .await?
            .and_then(|value| management::carrying_interface(&client.rci, &value));
        let available_components = optional_show(&client.rci, ["components", "list"])
            .await?
            .map_or_else(BTreeSet::new, |value| component_names(&value));
        let initial_setup = InitialSetupState {
            eula: optional_show(&client.rci, ["show", "eula", "list"]).await?,
            easyconfig: optional_show(&client.rci, ["easyconfig", "status"]).await?,
        };
        let realm = probe_realm(&client.rci).await?;
        let fail_safe_available = matches!(info.system_mode, Some(SystemMode::Router));
        let installed_components = info.components.clone();
        let system_mode = info.system_mode.clone();
        let startup_config_md5 = startup_config.header.md5.clone();
        let last_change_checksum = collect_last_change(&client.rci).await?;
        let management_url = client.router.as_str().to_owned();
        let login = client.rci.credentials().login;
        Ok(Self {
            info,
            catalog,
            running_config,
            startup_config_md5,
            last_change_checksum,
            management_interface,
            management_url,
            login,
            ports,
            radios,
            usb_modems,
            installed_components,
            available_components,
            system_mode,
            fail_safe_available,
            realm,
            initial_setup,
            interfaces,
            interface_inventory,
        })
    }

    /// Whether a line about interface `name` may touch kcc's management connection: `name`
    /// is the [`management_interface`](Self::management_interface), or, when that is
    /// unknown, any bridge.
    #[inline]
    #[must_use]
    pub fn may_carry_management(&self, name: &str) -> bool {
        management::may_carry(self.management_interface.as_deref(), name)
    }
}

/// Extracts every interface id from the authoritative interface-list response.
fn interface_names(value: &Value) -> Option<BTreeSet<String>> {
    Some(value.as_object()?.keys().cloned().collect())
}

/// Reads the live running checksum rather than relying on optional export header metadata.
///
/// # Errors
/// Returns transport or malformed checksum failures.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, the show operation is read-only.
async fn collect_last_change(client: &RciClient) -> Result<String, RciError> {
    let path =
        RciPath::from_segments(["show", "last-change"]).map_err(|_error| RciError::Validation)?;
    let RciBody::Json(response) = client.get(&path, &()).await? else {
        return Err(RciError::Decode);
    };
    let checksum = response
        .value
        .get("checksum")
        .and_then(Value::as_str)
        .ok_or(RciError::Decode)?;
    if checksum.len() != 32 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RciError::Decode);
    }
    Ok(checksum.to_owned())
}

/// Target inventory failures.
#[derive(Debug, Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public error type identifies its inventory domain"
)]
pub enum InventoryError {
    /// Source firmware was unknown and no explicit value was supplied.
    #[error("source firmware version must be supplied explicitly")]
    SourceVersionRequired,
    /// Target firmware is below 4.3 or unknown.
    #[error("target firmware is older than 4.3 or unknown")]
    UnsupportedFirmware,
    /// Target firmware is older than the source firmware.
    #[error("target firmware {target_version} is older than source firmware {source_version}")]
    TargetFirmwareOlder {
        /// Source firmware.
        source_version: FirmwareVersion,
        /// Target firmware.
        target_version: FirmwareVersion,
    },
    /// Router read failed.
    #[error("target inventory read failed")]
    Rci(#[from] RciError),
    /// Running configuration is not UTF-8.
    #[error("running configuration is not UTF-8")]
    ConfigEncoding,
    /// Running configuration syntax is malformed.
    #[error("running configuration could not be parsed")]
    Parse(#[from] ParseError),
    /// Generated catalog data is malformed.
    #[error("target catalog could not be loaded")]
    Catalog,
}

/// Converts detected physical ports into role-labelled entries.
fn collect_ports(info: &RouterInfo) -> Vec<PhysicalPort> {
    info.interfaces
        .as_ref()
        .into_iter()
        .flat_map(|inventory| inventory.ports.iter())
        .enumerate()
        .map(|(index, port)| {
            let role = classify_port(port.label.as_deref(), index);
            let label = port.label.clone().unwrap_or_else(|| port_label(&role));
            PhysicalPort {
                id: port.id.clone(),
                label,
                role,
            }
        })
        .collect()
}

/// Classifies a port from its case label, falling back to ordered switch roles.
fn classify_port(label: Option<&str>, index: usize) -> PortRole {
    let normalized = label.unwrap_or_default().to_ascii_uppercase();
    if normalized.contains("SFP") {
        PortRole::Sfp
    } else if normalized.contains("DSL") {
        PortRole::Dsl
    } else if normalized.contains("WAN") || index == 0 {
        PortRole::Wan
    } else {
        PortRole::Lan(u16::try_from(index).unwrap_or(u16::MAX))
    }
}

/// Produces a stable human label for an inferred role.
fn port_label(role: &PortRole) -> String {
    match role {
        PortRole::Wan => "WAN".to_owned(),
        PortRole::Lan(number) => format!("LAN {number}"),
        PortRole::Sfp => "SFP".to_owned(),
        PortRole::Dsl => "DSL".to_owned(),
        PortRole::Other(name) => name.clone(),
    }
}

/// Collects radios, supplementing missing band endpoints with hardware feature flags.
fn collect_radios(info: &RouterInfo) -> Vec<Radio> {
    let fallback = feature_bands(&info.features);
    info.interfaces
        .as_ref()
        .into_iter()
        .flat_map(|inventory| inventory.radios.iter())
        .map(|radio| {
            let parsed = radio.bands.as_ref().map_or_else(BTreeSet::new, |bands| {
                bands.iter().filter_map(|band| parse_band(band)).collect()
            });
            Radio {
                id: radio.id.clone(),
                bands: if parsed.is_empty() {
                    fallback.clone()
                } else {
                    parsed
                },
            }
        })
        .collect()
}

/// Maps reported band text.
fn parse_band(value: &str) -> Option<RadioBand> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("2.4") || lower.contains("2ghz") {
        Some(RadioBand::Ghz2_4)
    } else if lower.contains('5') {
        Some(RadioBand::Ghz5)
    } else if lower.contains('6') {
        Some(RadioBand::Ghz6)
    } else {
        None
    }
}

/// Maps `show version` feature flags to bands.
fn feature_bands(features: &BTreeSet<String>) -> BTreeSet<RadioBand> {
    features
        .iter()
        .filter_map(|feature| parse_band(feature))
        .collect()
}

/// Extracts named interfaces from top-level configuration contexts.
fn collect_interfaces(ast: &Ast) -> (Vec<String>, Vec<LogicalInterface>) {
    let interfaces = ast
        .nodes
        .iter()
        .filter_map(|node| match node.tokens.as_slice() {
            [Token::Word(command), Token::Word(name), ..] if command == "interface" => {
                Some(LogicalInterface {
                    name: name.clone(),
                    kind: interface_kind(name),
                    target_default: true,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let usb_modems = interfaces
        .iter()
        .filter(|interface| interface.kind == "UsbModem")
        .map(|interface| interface.name.clone())
        .collect();
    (usb_modems, interfaces)
}

/// Infers an interface type from Keenetic object naming conventions.
#[must_use]
pub(crate) fn interface_kind(name: &str) -> String {
    [
        "Bridge",
        "Vlan",
        "PPPoE",
        "Wireguard",
        "UsbModem",
        "OpenVPN",
        "SSTP",
        "L2TP",
        "PPTP",
        "IPSec",
    ]
    .into_iter()
    .find(|prefix| name.starts_with(prefix))
    .unwrap_or("Other")
    .to_owned()
}

/// Reads an optional JSON show/action endpoint without performing a mutation.
///
/// # Errors
///
/// Returns transport, authentication, decode, or response-size failures.
// NOT cancel-safe: it only sends one `show` read, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
async fn optional_show<const SIZE: usize>(
    client: &RciClient,
    segments: [&str; SIZE],
) -> Result<Option<Value>, RciError> {
    let path = RciPath::from_segments(segments).map_err(|_error| RciError::Validation)?;
    match client.show(&path, &()).await {
        Ok(RciBody::Json(response)) => Ok(Some(response.value)),
        Ok(RciBody::Text(_) | _)
        | Err(
            RciError::NotFound
            | RciError::MethodNotAllowed
            | RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _,
            },
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Recursively extracts component names from common response fields.
fn component_names(value: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Object(object) => {
                if let Some(name) = object.get("name").and_then(Value::as_str) {
                    let _: bool = names.insert(name.to_owned());
                }
                stack.extend(object.values());
            }
            Value::Array(values) => stack.extend(values),
            Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {}
        }
    }
    names
}

/// Probes the unauthenticated challenge realm without retaining challenge secrets.
///
/// # Errors
///
/// Returns transport failures when the challenge cannot be fetched.
// cancel-safe: the read-only probe uses the client's admission permit.
async fn probe_realm(client: &RciClient) -> Result<Option<String>, InventoryError> {
    let headers = client.auth_headers().await?;
    if let Some(value) = headers
        .get("x-ndm-realm")
        .and_then(|value| value.to_str().ok())
    {
        return Ok(Some(value.to_owned()));
    }
    Ok(headers
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(challenge_realm))
}

/// Extracts a quoted realm parameter from an authentication challenge.
fn challenge_realm(challenge: &str) -> Option<String> {
    let tail = challenge.split_once("realm=\"")?.1;
    Some(tail.split_once('"')?.0.to_owned())
}

/// Parses a firmware title for callers preparing explicit source input.
///
/// # Errors
///
/// Returns the shared firmware parser error for malformed text.
#[inline]
pub fn source_version(value: &str) -> Result<FirmwareVersion, FirmwareVersionError> {
    FirmwareVersion::from_str(value)
}
