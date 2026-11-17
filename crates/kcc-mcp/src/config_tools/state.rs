//! `kcc_config_state` and `kcc_config_save`.

use kcc_app::permissions::Permission;
use kcc_domain::configuration::read_last_change;
use serde_json::{Value, json};

use super::backups::RouterInput;
use crate::{
    KccMcp, McpFailure,
    support::{
        errors::{map_domain, map_workflow},
        route::parse,
    },
};

/// Reads unsaved state, fail-safe state, and the last change of a router.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn config_state(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: RouterInput = parse(arguments)?;
    let (_identity, router) = server.authorize_host(Permission::Read, input.into_host())?;
    let ctx = server.router_ctx(&router).await?;
    let state = read_last_change(&ctx).await.map_err(map_domain)?;
    let fail_safe = state.fail_safe.unwrap_or_default();
    Ok(json!({
        "host": router.as_str(),
        "unsaved": state.unsaved,
        "fail_safe": {
            "active": fail_safe.active.unwrap_or(false),
            "remaining_seconds": fail_safe.remaining
        },
        "last_change": {
            "agent": state.agent,
            "user": state.user,
            "checksum": state.checksum
        }
    }))
}

/// Explicitly saves a router's running configuration.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn config_save(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: RouterInput = parse(arguments)?;
    let (identity, router) = server.authorize_host(Permission::Save, input.into_host())?;
    let mut changes = server.begin_change(&router, &identity).await?;
    changes.save().await.map_err(map_workflow)?;
    Ok(json!({ "saved": true, "unsaved": false }))
}
