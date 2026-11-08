//! Catalog metadata and firmware selection types.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_rci::version::FirmwareVersion;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A generated catalog line.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum CatalogVersion {
    /// KeeneticOS 4.3.
    V4_3,
    /// KeeneticOS 5.0.
    V5_0,
    /// KeeneticOS 5.1.
    V5_1,
}

impl CatalogVersion {
    /// Returns the generated directory name.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4_3 => "4.3",
            Self::V5_0 => "5.0",
            Self::V5_1 => "5.1",
        }
    }

    /// Selects the newest documented line not newer than `firmware`.
    ///
    /// # Errors
    /// Returns [`CatalogError::UnsupportedFirmware`] for firmware older than 4.3.
    pub(crate) fn for_firmware(firmware: FirmwareVersion) -> Result<Self, CatalogError> {
        match firmware.line() {
            line if line >= (5, 1) => Ok(Self::V5_1),
            line if line >= (5, 0) => Ok(Self::V5_0),
            line if line >= (4, 3) => Ok(Self::V4_3),
            _ => Err(CatalogError::UnsupportedFirmware),
        }
    }
}

/// How the hardware model was matched to generated manuals.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ModelMatch {
    /// Commands are limited to one model's manuals.
    Exact(String),
    /// All models in the selected version are combined.
    Union,
}

/// Catalog command category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommandKind {
    /// Persistent or running configuration.
    Setting,
    /// Read-oriented command.
    Show,
    /// Immediate operation.
    Action,
}

/// One argument's validation category.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArgumentKind {
    /// Signed integer, optionally bounded.
    Integer,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// IPv4 netmask.
    IpMask,
    /// Address with a prefix length.
    IpAddressMask,
    /// MAC address.
    MacAddress,
    /// RCI object/interface name.
    ObjectName,
    /// One of a fixed set of words.
    Keyword,
    /// Unconstrained textual catalog value.
    String,
    /// Sensitive text.
    Password,
}

/// One generated command argument.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Argument {
    /// JSON member name.
    pub name: String,
    /// Validation category.
    pub kind: ArgumentKind,
    /// Accepted keyword values.
    pub values: Vec<String>,
    /// Inclusive lower bound.
    pub minimum: Option<i64>,
    /// Inclusive upper bound.
    pub maximum: Option<i64>,
}

/// One generated command available in a catalog view.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Command {
    /// Space-separated CLI path.
    pub path: String,
    /// Models whose manuals contain the command.
    pub models: BTreeSet<String>,
    /// Command category.
    pub kind: CommandKind,
    /// Whether the CLI `no` prefix is supported.
    pub prefix_no: bool,
    /// Named request arguments.
    pub arguments: BTreeMap<String, Argument>,
    /// Whether the router saves the command itself at once: no configuration save is
    /// needed and the fail-safe timer cannot roll it back.
    pub persists_immediately: bool,
}

/// Coarse authorization and confirmation risk.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
pub enum Risk {
    /// Read-only request.
    Read,
    /// Ordinary configuration mutation.
    Write,
    /// Connectivity or account management mutation.
    Management,
    /// Data-loss, reboot, or irreversible operation.
    Destructive,
}

/// Catalog construction errors.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum CatalogError {
    /// Firmware is absent or too old.
    #[error("firmware is older than the 4.3 catalog")]
    UnsupportedFirmware,
    /// A committed artifact could not be decoded.
    #[error("generated catalog data is invalid")]
    InvalidGeneratedCatalog,
}
