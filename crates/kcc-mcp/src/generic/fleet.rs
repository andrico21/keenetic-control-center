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
        audit::Success,
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

impl ListInput {
    /// The projection members and page offset that shape the reply.
    pub(crate) fn shape_input(&self) -> (Vec<String>, Option<usize>) {
        shape_input(self.fields.as_deref(), self.cursor.as_deref())
    }
}

impl CatalogSearchInput {
    /// The projection members and page offset that shape the reply.
    pub(crate) fn shape_input(&self) -> (Vec<String>, Option<usize>) {
        shape_input(self.fields.as_deref(), self.cursor.as_deref())
    }
}

/// The requested members and the page offset; an unparsable cursor fails the tool itself.
fn shape_input(fields: Option<&[String]>, cursor: Option<&str>) -> (Vec<String>, Option<usize>) {
    (
        fields.unwrap_or_default().to_vec(),
        Some(parse_cursor(cursor).unwrap_or(0)),
    )
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
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn routers_list(server: &KccMcp, input: &ListInput) -> Result<Value, McpFailure> {
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
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only reads router state, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
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
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only detects the router and searches its catalog, but it may sign in first,
// and a sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn catalog_search(
    server: &KccMcp,
    input: CatalogSearchInput,
) -> Result<Value, McpFailure> {
    valid_text(&input.query, MAX_QUERY_CHARS)?;
    validate_fields(input.fields.as_deref())?;
    let (_identity, host) = server.authorize_host(Permission::Read, input.host)?;
    let catalog = server.catalog(host.as_str()).await?;
    let limit = usize::from(input.limit.unwrap_or(20).clamp(1, 100));
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
        "next_cursor": (results.len() == limit).then(|| offset.saturating_add(limit).to_string())
    }))
}

/// Returns one command's JSON schema.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only detects the router and describes a catalog command, but it may sign in
// first, and a sign-in dropped mid-way can leave an orphaned router session.
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
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn job_status(server: &KccMcp, input: &JobInput) -> Result<Value, McpFailure> {
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

/// The permission that cancels a job of `kind`: `Destructive` for the Entware jobs,
/// which only that permission may start, `Write` for every other job.
fn cancel_permission(kind: &str) -> Permission {
    if kind.starts_with("entware.") {
        Permission::Destructive
    } else {
        Permission::Write
    }
}

/// Cancels one job the caller may write.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: the job may be cancelled, and its audit entry queued, before the future is
// dropped.
pub(crate) async fn job_cancel(server: &KccMcp, input: JobInput) -> Result<Value, McpFailure> {
    valid_job_id(&input.id)?;
    let identity = server.identity()?;
    let record = server.jobs.get(&input.id).map_err(|error| {
        tracing::warn!(job = input.id, error = ?error, "MCP job lookup failed");
        McpFailure::InvalidArguments
    })?;
    let needed = cancel_permission(&record.kind);
    match &record.router {
        Some(router) => {
            authorize(&identity.role, needed, router).map_err(|_error| McpFailure::Forbidden)?;
        }
        None if !identity.role.grants(needed) => {
            return Err(McpFailure::Forbidden);
        }
        None => {}
    }
    server.jobs.cancel(&input.id).await.map_err(|error| {
        tracing::warn!(job = input.id, error = ?error, "MCP job cancellation failed");
        McpFailure::Conflict
    })?;
    let mut done = Success::new("kcc_job_cancel")
        .with_target(record.kind)
        .with_params(json!({ "id": input.id }));
    if let Some(router) = &record.router {
        done = done.on_router(router);
    }
    Ok(done.record(server, json!({ "cancelled": true })).await)
}
