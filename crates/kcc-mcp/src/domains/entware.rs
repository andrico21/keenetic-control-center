//! The `entware` toolset: `kcc_entware_read` and `kcc_entware_write`, over the router API.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::entware;
use rmcp::handler::server::router::tool::ToolRoute;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::write::entware::{EntwareInput, meta, ops, write};
use crate::{
    KccMcp, McpFailure,
    registry::definitions::ToolDescription,
    support::{
        errors::map_domain,
        route::{ToolFuture, parse, route, schema_with_ops},
    },
};

/// The toolset of both Entware tools.
const TOOLSET: &str = "entware";

/// Read operations.
const READ_OPS: &[&str] = &["status", "settings", "drives"];

/// Arguments of `kcc_entware_read`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntwareReadInput {
    /// Router profile id.
    host: String,
    /// Read operation.
    op: String,
}

/// The read tool.
fn read_tool() -> ToolDescription {
    ToolDescription::single(
        "kcc_entware_read",
        "Read whether Entware can run (components, architecture), its opkg settings, and the drives it can use or initialize",
        TOOLSET,
        Permission::Read,
        (true, false, true),
    )
    .with_ops(READ_OPS.to_vec())
}

/// The write tool, gated by the least permission of its operations.
fn write_tool() -> ToolDescription {
    let metas = ops().into_iter().filter_map(meta).collect::<Vec<_>>();
    let permission = metas
        .iter()
        .map(|&(permission, _risk)| permission)
        .min()
        .unwrap_or(Permission::Destructive);
    let destructive = metas
        .iter()
        .any(|&(_permission, risk)| risk == Risk::Destructive);
    ToolDescription::single(
        "kcc_entware_write",
        "Start the Entware setup job on a drive (arch is required when the status reports mips_ambiguous), change the opkg chroot, time zone, init script or DNS override, or remove Entware; never saves",
        TOOLSET,
        permission,
        (false, destructive, false),
    )
    .with_ops(ops())
}

/// Both Entware tool descriptions.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    vec![read_tool(), write_tool()]
}

/// Routes of both Entware tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    vec![
        route(
            &read_tool(),
            schema_with_ops::<EntwareReadInput>(READ_OPS),
            |server, arguments, _progress| -> ToolFuture<'_> { Box::pin(read(server, arguments)) },
        ),
        route(
            &write_tool(),
            schema_with_ops::<EntwareInput>(&ops()),
            |server, arguments, progress| -> ToolFuture<'_> {
                Box::pin(write(server, arguments, progress))
            },
        ),
    ]
}

/// Runs one `kcc_entware_read` call.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only reads router state, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
async fn read(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: EntwareReadInput = parse(arguments)?;
    if !READ_OPS.contains(&input.op.as_str()) {
        return Err(McpFailure::InvalidArguments);
    }
    let (_identity, host) = server.authorize_host(Permission::Read, input.host.clone())?;
    let ctx = server.router_ctx(&host).await?;
    let value = if input.op == "settings" {
        json!(entware::read_settings(&ctx).await.map_err(map_domain)?)
    } else {
        let status = entware::read_status(&ctx).await.map_err(map_domain)?;
        if input.op == "drives" {
            json!({ "drives": status.drives, "initializable": status.initializable })
        } else {
            json!(status)
        }
    };
    Ok(json!({ "op": input.op, "value": value }))
}
