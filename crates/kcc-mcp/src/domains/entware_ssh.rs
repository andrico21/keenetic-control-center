//! The `entware-ssh` toolset: `kcc_entware_packages` and `kcc_entware_services`, Entware
//! package and service operations over the enrolled router's pinned SSH session.
//!
//! Every operation, reads included, needs `Destructive` on the router, `allow_destructive`
//! and `confirm: true`. Names are checked against kcc-ssh's grammars before the router is
//! contacted; reads answer parsed values directly, mutations start a write job and answer
//! its id. Nothing enrols over MCP: probe, bootstrap, re-pin and revoke stay on the Web UI
//! and the CLI, so the Entware password never passes through a model provider.

use kcc_app::permissions::Permission;
use kcc_domain::entware::ssh::ops::{ServiceVerb, job::Mutation, names};
use rmcp::handler::server::router::tool::ToolRoute;
use schemars::JsonSchema;
use serde::Deserialize;

use super::write::entware_ssh::{Call, Read, Target, run};
use crate::{
    KccMcp, McpFailure,
    registry::definitions::ToolDescription,
    support::{
        route::{ToolFuture, parse, route, schema_with_ops},
        validate::parse_cursor,
    },
};

/// The toolset of both tools.
const TOOLSET: &str = "entware-ssh";

/// The package tool.
const PACKAGES: &str = "kcc_entware_packages";

/// The service tool.
const SERVICES: &str = "kcc_entware_services";

/// Package operations.
const PACKAGE_OPS: &[&str] = &[
    "list",
    "upgradable",
    "update",
    "install",
    "remove",
    "upgrade",
];

/// Service operations.
const SERVICE_OPS: &[&str] = &["list", "status", "start", "stop", "restart", "log"];

/// Log records of a `log` read when the call names no count.
const DEFAULT_LOG_LINES: u32 = 100;

/// Most log records of one `log` read.
const MAX_LOG_LINES: u32 = 1000;

/// Arguments of `kcc_entware_packages`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackagesInput {
    /// Router profile id.
    host: String,
    /// Operation; every one, reads included, is destructive.
    op: String,
    /// Confirmation, required for every operation.
    #[serde(default)]
    confirm: bool,
    /// `install`, `remove` and `upgrade`: the package name, `[a-z0-9][a-z0-9+._-]{0,63}`.
    #[serde(default)]
    package: Option<String>,
    /// `list` and `upgradable`: the `next_cursor` of the previous page.
    #[serde(default)]
    cursor: Option<String>,
}

/// Arguments of `kcc_entware_services`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServicesInput {
    /// Router profile id.
    host: String,
    /// Operation; every one, reads included, is destructive.
    op: String,
    /// Confirmation, required for every operation.
    #[serde(default)]
    confirm: bool,
    /// Every operation but `list`: the init script, `S<two digits><name>` as `list` reports.
    #[serde(default)]
    service: Option<String>,
    /// `log`: the newest records to return, 1 to 1000 (default 100).
    #[serde(default)]
    max_lines: Option<u32>,
    /// `list` and `log`: the `next_cursor` of the previous page.
    #[serde(default)]
    cursor: Option<String>,
}

/// One tool of the toolset: `Destructive`, destructive-hinted, never read-only.
fn tool(name: &'static str, description: &'static str, ops: &[&'static str]) -> ToolDescription {
    ToolDescription::single(
        name,
        description,
        TOOLSET,
        Permission::Destructive,
        (false, true, false),
    )
    .with_ops(ops.to_vec())
}

/// The package tool.
fn packages_tool() -> ToolDescription {
    tool(
        PACKAGES,
        "List installed or upgradable Entware packages, or update the package lists, install, remove or upgrade one package over the router's pinned SSH session; mutations run as jobs; every operation is destructive",
        PACKAGE_OPS,
    )
}

/// The service tool.
fn services_tool() -> ToolDescription {
    tool(
        SERVICES,
        "List Entware services, read one's state or its log records (none found and a log the router answers as text both read as no records), or start, stop or restart it over the router's pinned SSH session; actions run as jobs; every operation is destructive",
        SERVICE_OPS,
    )
}

/// Both tool descriptions.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    vec![packages_tool(), services_tool()]
}

/// Routes of both tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    vec![
        route(
            &packages_tool(),
            schema_with_ops::<PackagesInput>(PACKAGE_OPS),
            |server, arguments, progress| -> ToolFuture<'_> {
                Box::pin(async move {
                    let input: PackagesInput = parse(arguments)?;
                    let call = package_call(&input)?;
                    let target = Target::new(PACKAGES, (input.host, input.confirm), call);
                    run(server, target, progress).await
                })
            },
        ),
        route(
            &services_tool(),
            schema_with_ops::<ServicesInput>(SERVICE_OPS),
            |server, arguments, progress| -> ToolFuture<'_> {
                Box::pin(async move {
                    let input: ServicesInput = parse(arguments)?;
                    let call = service_call(&input)?;
                    let target = Target::new(SERVICES, (input.host, input.confirm), call);
                    run(server, target, progress).await
                })
            },
        ),
    ]
}

/// The page offset of a listing operation; a cursor on any other operation is refused.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn offset(listing: bool, cursor: Option<&str>) -> Result<usize, McpFailure> {
    if !listing && cursor.is_some() {
        return Err(McpFailure::InvalidArguments);
    }
    parse_cursor(cursor)
}

/// The checked call of `input`: the operation with its parsed package name.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn package_call(input: &PackagesInput) -> Result<Call, McpFailure> {
    let op = input.op.as_str();
    let offset = offset(matches!(op, "list" | "upgradable"), input.cursor.as_deref())?;
    let package =
        |name: &str| names::package(name).map_err(|_grammar| McpFailure::InvalidArguments);
    Ok(match (op, input.package.as_deref()) {
        ("list", None) => Call::Read(Read::Packages {
            upgradable: false,
            offset,
        }),
        ("upgradable", None) => Call::Read(Read::Packages {
            upgradable: true,
            offset,
        }),
        ("update", None) => Call::Mutation(Mutation::Update),
        ("install", Some(name)) => Call::Mutation(Mutation::Install(package(name)?)),
        ("remove", Some(name)) => Call::Mutation(Mutation::Remove(package(name)?)),
        ("upgrade", Some(name)) => Call::Mutation(Mutation::Upgrade(package(name)?)),
        _ => return Err(McpFailure::InvalidArguments),
    })
}

/// The checked call of `input`: the operation with its checked service name.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn service_call(input: &ServicesInput) -> Result<Call, McpFailure> {
    let op = input.op.as_str();
    let offset = offset(matches!(op, "list" | "log"), input.cursor.as_deref())?;
    if op != "log" && input.max_lines.is_some() {
        return Err(McpFailure::InvalidArguments);
    }
    let invalid = |_grammar| McpFailure::InvalidArguments;
    let action = |name: &str, verb| {
        Ok(Call::Mutation(Mutation::Service(
            names::service(name).map_err(invalid)?,
            verb,
        )))
    };
    let checked = |name: &str| {
        names::service(name)
            .map(|_parsed| name.to_owned())
            .map_err(invalid)
    };
    match (op, input.service.as_deref()) {
        ("list", None) => Ok(Call::Read(Read::Services { offset })),
        ("status", Some(name)) => Ok(Call::Read(Read::Status(checked(name)?))),
        ("start", Some(name)) => action(name, ServiceVerb::Start),
        ("stop", Some(name)) => action(name, ServiceVerb::Stop),
        ("restart", Some(name)) => action(name, ServiceVerb::Restart),
        ("log", Some(name)) => {
            let lines = input.max_lines.unwrap_or(DEFAULT_LOG_LINES);
            if !(1..=MAX_LOG_LINES).contains(&lines) {
                return Err(McpFailure::InvalidArguments);
            }
            Ok(Call::Read(Read::Log {
                service: checked(name)?,
                lines,
                offset,
            }))
        }
        _ => Err(McpFailure::InvalidArguments),
    }
}
