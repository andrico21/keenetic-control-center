//! Fleet, catalog, and job tools.

use kcc_app::{
    permissions::Permission,
    registry::{authorize, scope_matches},
};
use kcc_rci::capabilities::SupportTier;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::persists::labelled;
use crate::{
    KccMcp, McpFailure,
    support::{
        names,
        validate::{
            MAX_PATH_CHARS, MAX_QUERY_CHARS, paginate, parse_cursor, valid_job_id, valid_text,
            validate_fields,
        },
    },
};

/// One router profile id.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostInput {
    /// Router profile id.
    host: String,
}

/// One page of the fleet.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListInput {
    /// Decimal offset cursor.
    #[serde(default)]
    cursor: Option<String>,
    /// Page size, at most 100.
    #[serde(default)]
    limit: Option<u16>,
    /// Projected fields.
    #[serde(default)]
    fields: Option<Vec<String>>,
}

/// A catalog search.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogSearchInput {
    /// Router profile id.
    host: String,
    /// Search text.
    query: String,
    /// Page size, at most 100.
    #[serde(default)]
    limit: Option<u16>,
    /// Decimal offset cursor.
    #[serde(default)]
    cursor: Option<String>,
    /// Projected fields.
    #[serde(default)]
    fields: Option<Vec<String>>,
}

/// One catalog command.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogDescribeInput {
    /// Router profile id.
    host: String,
    /// Catalog command path.
    path: String,
}

/// One background job id.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct JobInput {
    /// Job id.
    id: String,
}

/// Lists router profiles inside the caller's scope.
pub(crate) fn routers_list(server: &KccMcp, input: ListInput) -> Result<Value, McpFailure> {
    let _offset = parse_cursor(input.cursor.as_deref())?;
    validate_fields(input.fields.as_deref())?;
    let identity = server.identity()?;
    let mut items = server
        .registry
        .list()
        .map_err(|error| {
            tracing::error!(error = ?error, "MCP router list failed");
            McpFailure::Internal
        })?
        .into_iter()
        .filter(|entry| scope_matches(&identity.role.router_scope, &entry.profile.id))
        .map(|entry| {
            json!({
                "id": entry.profile.id,
                "tags": entry.profile.tags,
                "test_device": entry.profile.test_device
            })
        })
        .collect::<Vec<_>>();
    paginate(&mut items, input.cursor.as_deref(), input.limit)?;
    Ok(json!({ "routers": items }))
}

/// Reads router identity, firmware, capabilities, and support tier.
pub(crate) async fn router_info(server: &KccMcp, input: HostInput) -> Result<Value, McpFailure> {
    let (_identity, host) = server.authorize_host(Permission::Read, input.host)?;
    let info = server
        .registry
        .poll_info(host.as_str())
        .await
        .map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP router info failed");
            McpFailure::RouterUnreachable
        })?;
    let support_tier = match info.support_tier() {
        SupportTier::DocumentationBased => "documentation_based",
        SupportTier::HardwareVerified => "hardware_verified",
        SupportTier::Unsupported | _ => "unsupported",
    };
    Ok(json!({
        "host": host.as_str(),
        "model": info.version.model,
        "hardware_id": info.version.hw_id,
        "firmware": info.firmware.map(|version| version.to_string()),
        "brand": names::brand(info.brand),
        "components": info.components,
        "features": info.features,
        "support_tier": support_tier
    }))
}

/// Searches the router's catalog.
pub(crate) async fn catalog_search(
    server: &KccMcp,
    input: CatalogSearchInput,
) -> Result<Value, McpFailure> {
    valid_text(&input.query, MAX_QUERY_CHARS)?;
    validate_fields(input.fields.as_deref())?;
    let (_identity, host) = server.authorize_host(Permission::Read, input.host)?;
    let catalog = server.catalog(host.as_str()).await?;
    let limit = usize::from(input.limit.unwrap_or(20).min(100));
    let offset = parse_cursor(input.cursor.as_deref())?;
    let results = catalog
        .search(&input.query, offset.saturating_add(limit).saturating_add(1))
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|result| json!({ "path": result.command.path, "score": result.score }))
        .collect::<Vec<_>>();
    Ok(json!({
        "results": results,
        "next_cursor": (results.len() == limit).then(|| (offset + limit).to_string())
    }))
}

/// Returns one command's JSON schema.
pub(crate) async fn catalog_describe(
    server: &KccMcp,
    input: CatalogDescribeInput,
) -> Result<Value, McpFailure> {
    valid_text(&input.path, MAX_PATH_CHARS)?;
    let (_identity, host) = server.authorize_host(Permission::Read, input.host)?;
    let catalog = server.catalog(host.as_str()).await?;
    let schema = catalog
        .to_json_schema(&input.path)
        .ok_or(McpFailure::ValidationFailed)?;
    let persisted_paths = catalog
        .lookup(&input.path)
        .filter(|command| command.persists_immediately)
        .map_or_default(|_command| vec![input.path.clone()]);
    let persists = !persisted_paths.is_empty();
    Ok(labelled(
        json!({ "path": input.path, "schema": schema, "persisted_paths": persisted_paths }),
        persists,
        &[],
    ))
}

/// Reads one job inside the caller's router scope.
pub(crate) fn job_status(server: &KccMcp, input: JobInput) -> Result<Value, McpFailure> {
    valid_job_id(&input.id)?;
    let identity = server.identity()?;
    let record = server.jobs.get(&input.id).map_err(|error| {
        tracing::warn!(job = input.id, error = ?error, "MCP job lookup failed");
        McpFailure::InvalidArguments
    })?;
    if let Some(router) = &record.router {
        authorize(&identity.role, Permission::Read, router)
            .map_err(|_error| McpFailure::Forbidden)?;
    }
    serde_json::to_value(record).map_err(|error| {
        tracing::error!(error = ?error, "MCP job serialization failed");
        McpFailure::Internal
    })
}

/// Cancels one job the caller may write.
pub(crate) async fn job_cancel(server: &KccMcp, input: JobInput) -> Result<Value, McpFailure> {
    valid_job_id(&input.id)?;
    let identity = server.identity()?;
    let record = server.jobs.get(&input.id).map_err(|error| {
        tracing::warn!(job = input.id, error = ?error, "MCP job lookup failed");
        McpFailure::InvalidArguments
    })?;
    match &record.router {
        Some(router) => authorize(&identity.role, Permission::Write, router)
            .map_err(|_error| McpFailure::Forbidden)?,
        None if !identity.role.grants(Permission::Write) => {
            return Err(McpFailure::Forbidden);
        }
        None => {}
    }
    server.jobs.cancel(&input.id).await.map_err(|error| {
        tracing::warn!(job = input.id, error = ?error, "MCP job cancellation failed");
        McpFailure::Conflict
    })?;
    Ok(json!({ "cancelled": true }))
}
