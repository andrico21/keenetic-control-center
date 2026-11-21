//! Entware status and `opkg` settings models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The router's `opkg` settings from the running configuration.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(from = "RawSettings")]
#[non_exhaustive]
pub struct EntwareSettings {
    /// The `opkg disk` argument, such as `<label>:/`.
    pub disk: Option<String>,
    /// The `opkg initrc` script path.
    pub initrc: Option<String>,
    /// The `opkg timezone` setting.
    pub timezone: Option<TimezoneSetting>,
    /// Whether `opkg chroot` is on.
    pub chroot: bool,
    /// Whether `opkg dns-override` is on.
    pub dns_override: bool,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The `opkg timezone` setting.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimezoneSetting {
    /// `opkg timezone auto`: the router's own time zone.
    Auto,
    /// A named time zone.
    Named(String),
}

/// Whether Entware can be installed on the router.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Possibility {
    /// The router has USB and storage support and a known architecture.
    Possible,
    /// The router's firmware lacks the `usb` or the `storage` component.
    NoUsbOrStorage,
    /// The router reports an architecture no installer exists for.
    UnsupportedArch(String),
}

/// Presence of one firmware component.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComponentPresence {
    /// Installed in the running firmware.
    Installed,
    /// Listed by the router as installable.
    Available,
    /// Neither installed nor offered.
    Missing,
}

/// The installer family the router's `show version` architecture selects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchResolution {
    /// `aarch64`: the aarch64 installer.
    Aarch64,
    /// `mips`, reported by little- and big-endian models alike: the user picks the installer.
    MipsAmbiguous,
    /// Any other value, or none (empty text).
    Unknown(String),
}

/// One drive `opkg disk` can use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct EligibleDrive {
    /// Router media identifier.
    pub media_id: String,
    /// The `opkg disk` argument: `<label>:/` or `<uuid>:/`.
    pub disk_arg: String,
    /// Volume label.
    pub label: Option<String>,
    /// Filesystem type (ext2, ext3 or ext4).
    pub filesystem: String,
    /// Free bytes.
    pub free_bytes: Option<u64>,
}

/// Everything kcc needs to decide on and plan an Entware installation.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct EntwareStatus {
    /// Whether Entware can be installed.
    pub possible: Possibility,
    /// Presence of the `opkg` component.
    pub opkg_component: ComponentPresence,
    /// Presence of the `ext` component.
    pub ext_component: ComponentPresence,
    /// Current `opkg` settings.
    pub settings: EntwareSettings,
    /// Drives `opkg disk` can use.
    pub drives: Vec<EligibleDrive>,
    /// Media whose `initialize-supported` list contains `ext4`.
    pub initializable: Vec<String>,
    /// Architecture resolution from `show version`.
    pub arch: ArchResolution,
    /// Whether the DNS proxy's filter engine is `opkg`.
    pub dns_filter_uses_opkg: bool,
}

/// Entware installer archives (the closed installer table).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Installer {
    /// 64-bit ARM.
    Aarch64,
    /// Little-endian MIPS.
    Mipsel,
    /// Big-endian MIPS.
    Mips,
}

impl Installer {
    /// The installer archive URL `opkg disk` downloads.
    #[inline]
    #[must_use]
    pub const fn url(self) -> &'static str {
        match self {
            Self::Aarch64 => {
                "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz"
            }
            Self::Mipsel => {
                "https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz"
            }
            Self::Mips => "https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz",
        }
    }
}

/// The `opkg` tree of `show rc` as the router sends it: each setting either as a plain
/// value or as an object keyed by its catalog argument name.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RawSettings {
    /// `opkg disk`: text, or `{"disk": .., "url": ..}`.
    disk: Option<Value>,
    /// `opkg initrc`: text, or `{"path": ..}`.
    initrc: Option<Value>,
    /// `opkg timezone`: text, or `{"auto": true}` / `{"timezone": ..}`.
    timezone: Option<Value>,
    /// `opkg chroot`: a flag.
    chroot: Option<Value>,
    /// `opkg dns-override`: a flag.
    #[serde(rename = "dns-override")]
    dns_override: Option<Value>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl From<RawSettings> for EntwareSettings {
    #[inline]
    fn from(raw: RawSettings) -> Self {
        Self {
            disk: raw.disk.as_ref().and_then(|value| text(value, "disk")),
            initrc: raw.initrc.as_ref().and_then(|value| text(value, "path")),
            timezone: raw.timezone.as_ref().and_then(timezone),
            chroot: flag(raw.chroot.as_ref()),
            dns_override: flag(raw.dns_override.as_ref()),
            extra: raw.extra,
        }
    }
}

/// Non-empty text given plainly or under `key`.
fn text(value: &Value, key: &str) -> Option<String> {
    let found = match value {
        Value::String(plain) => Some(plain.as_str()),
        Value::Object(fields) => fields.get(key).and_then(Value::as_str),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) => None,
    };
    found.filter(|text| !text.is_empty()).map(str::to_owned)
}

/// The time zone given as `auto`, `{"auto": true}` or a name.
fn timezone(value: &Value) -> Option<TimezoneSetting> {
    if value.get("auto").is_some_and(|auto| flag(Some(auto))) {
        return Some(TimezoneSetting::Auto);
    }
    text(value, "timezone").map(|name| {
        if name == "auto" {
            TimezoneSetting::Auto
        } else {
            TimezoneSetting::Named(name)
        }
    })
}

/// Whether a flag is on: `true`, or present with any value other than `false` and `null`
/// (an unknown shape counts as on, the safe reading for `chroot`).
const fn flag(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(on)) => *on,
        Some(Value::Number(_) | Value::String(_) | Value::Array(_) | Value::Object(_)) => true,
    }
}
