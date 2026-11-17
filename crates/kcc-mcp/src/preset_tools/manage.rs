//! `kcc_preset_list` and `kcc_preset_delete`.

use kcc_app::permissions::Permission;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::state::{map_preset, view};
use crate::{
    KccMcp, McpFailure,
    support::{audit::Success, route::parse, validate::valid_text},
};

/// Arguments of `kcc_preset_list`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListInput {
    /// One preset (stored or transient) by id; omit to list every visible preset.
    #[serde(default)]
    id: Option<String>,
}

/// Arguments of `kcc_preset_delete`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteInput {
    /// Stored or transient preset id.
    id: String,
}

/// Lists presets whose source router the caller may read, or shows one; always redacted.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn list(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: ListInput = parse(arguments)?;
    let identity = server.identity()?;
    if !identity.role.grants(Permission::Read) {
        return Err(McpFailure::Forbidden);
    }
    let presets = &server.presets;
    if let Some(id) = input.id {
        valid_text(&id, 96)?;
        if let Some(preset) = presets.transient(&identity.name, &id).await? {
            return Ok(view(&preset, true));
        }
        let role = identity.role.clone();
        let stored = presets
            .stored(move |store| store.get(&role, &id))
            .await?
            .map_err(|error| map_preset(&error))?;
        return Ok(view(&stored, false));
    }
    let role = identity.role.clone();
    let mut views = presets
        .stored(move |store| store.list(&role))
        .await?
        .map_err(|error| map_preset(&error))?
        .iter()
        .map(|preset| view(preset, false))
        .collect::<Vec<_>>();
    views.extend(presets.transient_views(&identity.name).await);
    Ok(json!({ "presets": views }))
}

/// Deletes a stored preset, or forgets a transient one.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn delete(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: DeleteInput = parse(arguments)?;
    valid_text(&input.id, 96)?;
    let identity = server.identity()?;
    if !identity.role.grants(Permission::Migrate) {
        return Err(McpFailure::Forbidden);
    }
    let presets = &server.presets;
    if !presets.forget(&identity.name, &input.id).await? {
        let (role, id) = (identity.role.clone(), input.id.clone());
        presets
            .stored(move |store| store.delete(&role, &id))
            .await?
            .map_err(|error| map_preset(&error))?;
    }
    Ok(Success::new("kcc_preset_delete")
        .with_target(input.id.clone())
        .with_params(json!({ "id": input.id }))
        .record(server, json!({ "id": input.id, "deleted": true }))
        .await)
}
