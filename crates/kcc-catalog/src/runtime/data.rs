//! Lazy decoding of committed catalog shards.

use alloc::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::Deserialize;

use crate::{
    Argument, ArgumentKind, CatalogError, CatalogVersion, Command, CommandKind, cli::Synopsis,
    generated,
};

/// Parsed data shared by all router views of one firmware line.
#[derive(Debug)]
pub(super) struct CatalogData {
    /// Firmware line represented by this decoded data set.
    pub version: CatalogVersion,
    /// Commands keyed by their space-separated catalog path.
    pub commands: BTreeMap<String, Command>,
    /// Ordered manual grammar retained for conservative CLI parsing.
    pub synopses: BTreeMap<String, Synopsis>,
    /// Hardware models represented by the decoded command shards.
    pub models: BTreeSet<String>,
}

/// Generated shard envelope.
#[derive(Deserialize)]
struct Shard {
    /// Commands contained in this generated shard.
    commands: Vec<RawCommand>,
}

/// Generated command fields consumed at runtime.
#[derive(Deserialize)]
struct RawCommand {
    /// Space-separated command path.
    path: String,
    /// Models whose manuals contain the command.
    models: BTreeSet<String>,
    /// First firmware line containing the command.
    since: String,
    /// Generated command category.
    kind: CommandKind,
    /// Whether the command supports the CLI `no` prefix.
    prefix_no: bool,
    /// Whether the manual states that the router persists the command at once.
    #[serde(default)]
    persists_immediately: bool,
    /// Generated arguments keyed by request member name.
    arguments: BTreeMap<String, RawArgument>,
    /// Ordered CLI grammar, absent for undocumented command groups.
    synopsis: Option<Synopsis>,
    /// Incomplete manual extraction prevents confident CLI validation.
    #[serde(default)]
    parse_warnings: Vec<String>,
}

/// Generated argument fields consumed at runtime.
#[derive(Deserialize)]
struct RawArgument {
    /// Generated argument type name.
    #[serde(rename = "type")]
    kind: String,
    /// Accepted keyword values.
    #[serde(default)]
    values: Vec<String>,
    /// Inclusive generated minimum.
    #[serde(default, alias = "min")]
    minimum: Option<i64>,
    /// Inclusive generated maximum.
    #[serde(default, alias = "max")]
    maximum: Option<i64>,
}

/// Lazily decoded 4.3 data.
static V4_3: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V4_3));
/// Lazily decoded 5.0 data.
static V5_0: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V5_0));
/// Lazily decoded 5.1 data.
static V5_1: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V5_1));

/// Overlay paths whose responses represent cancellable background work.
pub(super) const BACKGROUND_PATHS: &[&str] = &[
    "tools ping",
    "tools ping6",
    "tools traceroute",
    "tools arping",
    "tools iperf3",
    "components list",
    "ussd send",
    "show log",
    "mws log",
];

/// Overlay paths that can erase data, reboot, or irreversibly mutate components.
pub(super) const DESTRUCTIVE_PATHS: &[&str] = &[
    "system reboot",
    "system configuration factory-reset",
    "system configuration fail-safe rollback",
    "system configuration fail-safe timer",
    "system configuration fail-safe keep-alive",
    "components commit",
    "erase",
    "copy",
    "media * format",
    "mws member reboot",
    "mws reboot",
    "system eject",
    "interface esim profile delete",
];

/// Overlay paths the router persists at once, without a configuration save
/// (`[[persists_immediately]]` in `catalog/overlay.toml`).
pub(super) const PERSISTS_IMMEDIATELY_PATHS: &[&str] = &["system country"];

/// Prefix rules affecting management access.
pub(super) const MANAGEMENT_PREFIXES: &[&str] = &[
    "user ",
    "ip http ",
    "ip ssh",
    "ip telnet",
    "service http",
    "service ssh",
    "service telnet",
    "cloud control2 security-level",
    "access-list ",
];

/// Exact command paths that can replace the management interface or its routing context.
pub(super) const MANAGEMENT_PATHS: &[&str] = &["ip route", "system mode"];

/// Interface command endings affecting management access.
pub(super) const MANAGEMENT_INTERFACE_SUFFIXES: &[&str] = &[
    " up",
    " down",
    " ip access-group",
    " security-level",
    " include",
    " inherit",
    " role",
    " schedule",
];

/// Interface command trees that can alter the address, uplink route, or link identity.
pub(super) const MANAGEMENT_INTERFACE_TREES: &[&str] = &[
    " ip address",
    " ipv6 address",
    " ip dhcp client",
    " ip global",
    " mac address",
    " mac clone",
];

/// Gets one lazily parsed data set.
///
/// # Errors
/// Returns [`CatalogError::InvalidGeneratedCatalog`] when embedded JSON is malformed.
pub(super) fn data(version: CatalogVersion) -> Result<&'static CatalogData, CatalogError> {
    match version {
        CatalogVersion::V4_3 => V4_3.as_ref().map_err(Clone::clone),
        CatalogVersion::V5_0 => V5_0.as_ref().map_err(Clone::clone),
        CatalogVersion::V5_1 => V5_1.as_ref().map_err(Clone::clone),
    }
}

/// Parses all generated command shards for one version.
///
/// # Errors
/// Returns [`CatalogError::InvalidGeneratedCatalog`] when an embedded shard is malformed.
fn load(version: CatalogVersion) -> Result<CatalogData, CatalogError> {
    let prefix = format!("catalog/{}/", version.as_str());
    let mut commands = BTreeMap::new();
    let mut synopses = BTreeMap::new();
    let mut models = BTreeSet::new();
    for (relative_path, contents) in generated::FILES {
        if !relative_path.starts_with(&prefix) || relative_path.ends_with("/index.json") {
            continue;
        }
        let shard: Shard = serde_json::from_str(contents)
            .map_err(|_error| CatalogError::InvalidGeneratedCatalog)?;
        for raw in shard.commands {
            if since_line(&raw.since).is_some_and(|line| line > version_line(version)) {
                continue;
            }
            models.extend(raw.models.iter().cloned());
            if raw.parse_warnings.is_empty()
                && let Some(synopsis) = raw.synopsis
            {
                drop(synopses.insert(raw.path.clone(), synopsis));
            }
            let arguments = raw
                .arguments
                .into_iter()
                .map(|(name, argument)| {
                    let kind = match argument.kind.as_str() {
                        "Integer" => ArgumentKind::Integer,
                        "IpAddress" | "Ipv6Address" => ArgumentKind::IpAddress,
                        "IpMask" | "Mask" => ArgumentKind::IpMask,
                        "IpAddressMask" => ArgumentKind::IpAddressMask,
                        "MacAddress" => ArgumentKind::MacAddress,
                        "Interface" | "ObjectName" => ArgumentKind::ObjectName,
                        "Keyword" => ArgumentKind::Keyword,
                        "Password" => ArgumentKind::Password,
                        _ => ArgumentKind::String,
                    };
                    let value = Argument {
                        name: name.clone(),
                        kind,
                        values: argument.values,
                        minimum: argument.minimum,
                        maximum: argument.maximum,
                    };
                    (name, value)
                })
                .collect();
            let command = Command {
                path: raw.path.clone(),
                models: raw.models,
                kind: raw.kind,
                prefix_no: raw.prefix_no,
                arguments,
                persists_immediately: raw.persists_immediately
                    || PERSISTS_IMMEDIATELY_PATHS
                        .iter()
                        .any(|pattern| super::path_matches(pattern, &raw.path)),
            };
            drop(commands.insert(raw.path, command));
        }
    }
    Ok(CatalogData {
        version,
        commands,
        synopses,
        models,
    })
}

/// Returns the firmware line represented by a generated catalog directory.
const fn version_line(version: CatalogVersion) -> (u16, u16) {
    match version {
        CatalogVersion::V4_3 => (4, 3),
        CatalogVersion::V5_0 => (5, 0),
        CatalogVersion::V5_1 => (5, 1),
    }
}

/// Parses the major/minor availability line from generated `since` text.
fn since_line(since: &str) -> Option<(u16, u16)> {
    let (major, minor) = since.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}
