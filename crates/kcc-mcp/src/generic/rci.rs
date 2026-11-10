//! Catalog-validated raw RCI and CLI tools.

use kcc_app::{
    permissions::Permission,
    workflow::{
        BatchChangeRequest, BatchItem, ChangeRequest, CliChangeRequest, CliCommand as ValidatedCli,
        DeleteRequest,
    },
};
use kcc_catalog::{Catalog, CommandKind, HttpMethod, RawAuthorization, Risk};
use kcc_rci::RciPath;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    persists::{applied, batch_applied, cli_applied},
    raw_change,
};
use crate::{
    KccMcp, McpFailure, authorize_routers,
    support::{
        errors::{map_rci, map_workflow, rci_body_value, statuses},
        validate::{
            MAX_BATCH_ITEMS, MAX_LINE_CHARS, empty_object, valid_host, valid_text,
            valid_value_size, validate_fields, validate_rci_input,
        },
    },
};

/// How a raw read reaches the router. Selector reads (`show rc`/`show sc`) are not offered:
/// the catalog holds no such commands, so what was validated could not be what was sent.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadKind {
    /// GET of a setting or show resource.
    #[default]
    Get,
}

/// One validated raw read.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RciReadInput {
    /// Router profile id.
    host: String,
    /// Catalog command path.
    catalog_path: String,
    /// RCI path segments.
    path: Vec<String>,
    /// Query or selector body.
    #[serde(default = "empty_object")]
    value: Value,
    /// Read transport.
    #[serde(default)]
    kind: ReadKind,
    /// Projected fields.
    #[serde(default)]
    fields: Option<Vec<String>>,
}

/// One validated raw mutation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RciWriteInput {
    /// Router profile id.
    host: String,
    /// Catalog command path.
    catalog_path: String,
    /// RCI path segments.
    path: Vec<String>,
    /// Request body.
    #[serde(default = "empty_object")]
    value: Value,
    /// Confirms a destructive request.
    #[serde(default)]
    confirm: bool,
}

/// A validated root batch.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RciBatchInput {
    /// Router profile id.
    host: String,
    /// Root request bodies.
    items: Vec<Value>,
    /// Confirms destructive items.
    #[serde(default)]
    confirm: bool,
}

/// One validated CLI line.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliInput {
    /// Router profile id.
    host: String,
    /// CLI line.
    line: String,
    /// Confirms a destructive line.
    #[serde(default)]
    confirm: bool,
}

impl RciReadInput {
    /// Router id retained for failure auditing.
    pub(crate) fn router(&self) -> &str {
        &self.host
    }
}

impl RciWriteInput {
    /// Router id retained for failure auditing.
    pub(crate) fn router(&self) -> &str {
        &self.host
    }
}

impl RciBatchInput {
    /// Router id retained for failure auditing.
    pub(crate) fn router(&self) -> &str {
        &self.host
    }
}

impl CliInput {
    /// Router id retained for failure auditing.
    pub(crate) fn router(&self) -> &str {
        &self.host
    }
}

/// Selects the generic catalog of a firmware line.
pub(crate) fn catalog_for_version(version: &str) -> Result<Catalog, McpFailure> {
    use kcc_rci::version::{FirmwareVersion, Stage};

    let firmware = match version {
        "4.3" => FirmwareVersion::new(4, 3, Stage::Release, 0, 0),
        "5.0" => FirmwareVersion::new(5, 0, Stage::Release, 0, 0),
        "5.1" => FirmwareVersion::new(5, 1, Stage::Release, 0, 0),
        _ => return Err(McpFailure::InvalidArguments),
    };
    Catalog::for_firmware_and_model(firmware, None).map_err(|_error| McpFailure::Internal)
}

/// Validates `value` for `catalog_path` and `method`, logging the issues.
fn checked(
    catalog: &Catalog,
    catalog_path: &str,
    method: HttpMethod,
    value: &Value,
) -> Result<kcc_catalog::ValidatedRequest, McpFailure> {
    catalog
        .validate(catalog_path, method, value)
        .map_err(|issues| {
            tracing::warn!(?issues, ?method, "MCP RCI validation failed");
            McpFailure::ValidationFailed
        })
}

/// Takes the strongest classification from every embedded catalog accepting the input.
fn preliminary_risk<F>(validate: F) -> Result<Risk, McpFailure>
where
    F: Fn(&Catalog) -> Result<kcc_catalog::ValidatedRequest, Vec<kcc_catalog::ValidationIssue>>,
{
    let mut risk: Option<Risk> = None;
    for version in ["4.3", "5.0", "5.1"] {
        if let Ok(request) = validate(&catalog_for_version(version)?) {
            risk = Some(risk.map_or(request.risk, |previous| previous.max(request.risk)));
        }
    }
    risk.ok_or(McpFailure::ValidationFailed)
}

/// Runs a catalog-validated read.
// cancel-safe: only validated reads reach the client, including show-only fallback POSTs.
pub(crate) async fn rci_read(server: &KccMcp, input: RciReadInput) -> Result<Value, McpFailure> {
    validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
    validate_fields(input.fields.as_deref())?;
    let ReadKind::Get = input.kind;
    let (_identity, host) = server.authorize_host(Permission::Read, input.host)?;
    let catalog = server.catalog(host.as_str()).await?;
    let _validated = checked(&catalog, &input.catalog_path, HttpMethod::Get, &input.value)?;
    let client = server
        .registry
        .client(host.as_str())
        .await
        .map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP RCI client failed");
            McpFailure::RouterUnreachable
        })?;
    let path =
        RciPath::from_segments(&input.path).map_err(|_error| McpFailure::InvalidArguments)?;
    let body = if catalog
        .lookup(&input.catalog_path)
        .is_some_and(|command| command.kind == CommandKind::Show)
    {
        client.show(&path, &input.value).await
    } else {
        client.get(&path, &input.value).await
    }
    .map_err(|error| map_rci(&error))?;
    Ok(rci_body_value(body))
}

/// Applies a catalog-validated mutation without saving.
// NOT cancel-safe: transmission can precede the workflow audit receipt.
pub(crate) async fn rci_execute(
    server: &KccMcp,
    input: RciWriteInput,
) -> Result<Value, McpFailure> {
    validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
    let (identity, host) = server.authorize_host(Permission::RawRci, input.host)?;
    let preliminary = preliminary_risk(|catalog| {
        catalog.validate(&input.catalog_path, HttpMethod::Post, &input.value)
    })?;
    raw_change::authorize(server, (&identity, &host), (preliminary, input.confirm))?;
    let catalog = server.catalog(host.as_str()).await?;
    let validated = checked(
        &catalog,
        &input.catalog_path,
        HttpMethod::Post,
        &input.value,
    )?;
    raw_change::authorize(
        server,
        (&identity, &host),
        (validated.risk.max(preliminary), input.confirm),
    )?;
    let result = raw_change::run(
        server,
        (&host, &identity, validated.contains_management()),
        async |changes| {
            changes
                .apply(ChangeRequest::new(
                    input.catalog_path,
                    input.path,
                    input.value,
                    Vec::new(),
                    Permission::RawRci,
                    json!({ "validated": true }),
                ))
                .await
                .map_err(map_workflow)
        },
    )
    .await?;
    Ok(applied(result.unsaved, &validated))
}

/// Applies a catalog-validated deletion without saving.
// NOT cancel-safe: transmission can precede the workflow audit receipt.
pub(crate) async fn rci_delete(server: &KccMcp, input: RciWriteInput) -> Result<Value, McpFailure> {
    validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
    let (identity, host) = server.authorize_host(Permission::RawRci, input.host)?;
    let preliminary = preliminary_risk(|catalog| {
        catalog.validate(&input.catalog_path, HttpMethod::Delete, &input.value)
    })?;
    raw_change::authorize(
        server,
        (&identity, &host),
        (preliminary.max(Risk::Destructive), input.confirm),
    )?;
    let catalog = server.catalog(host.as_str()).await?;
    let validated = checked(
        &catalog,
        &input.catalog_path,
        HttpMethod::Delete,
        &input.value,
    )?;
    raw_change::authorize(
        server,
        (&identity, &host),
        (validated.risk.max(Risk::Destructive), input.confirm),
    )?;
    let result = raw_change::run(
        server,
        (&host, &identity, validated.contains_management()),
        async |changes| {
            changes
                .apply_delete(DeleteRequest::new(
                    input.catalog_path,
                    input.path,
                    input.value,
                    Vec::new(),
                    Permission::RawRci,
                    json!({ "validated": true }),
                ))
                .await
                .map_err(map_workflow)
        },
    )
    .await?;
    Ok(applied(result.unsaved, &validated))
}

/// Applies a catalog-validated root batch without saving.
// NOT cancel-safe: transmission can precede the workflow audit receipt.
pub(crate) async fn rci_batch(server: &KccMcp, input: RciBatchInput) -> Result<Value, McpFailure> {
    valid_host(&input.host)?;
    if input.items.is_empty() || input.items.len() > MAX_BATCH_ITEMS {
        return Err(McpFailure::InvalidArguments);
    }
    let (identity, host) = server.authorize_host(Permission::RawRci, input.host)?;
    let mut risk = Risk::Read;
    for value in &input.items {
        valid_value_size(value)?;
        let preliminary =
            preliminary_risk(|catalog| catalog.validate("", HttpMethod::Post, value))?;
        risk = risk.max(preliminary);
        raw_change::authorize(server, (&identity, &host), (preliminary, input.confirm))?;
    }
    let catalog = server.catalog(host.as_str()).await?;
    let mut management = false;
    let mut items = Vec::with_capacity(input.items.len());
    for value in input.items {
        valid_value_size(&value)?;
        let validated = checked(&catalog, "", HttpMethod::Post, &value)?;
        risk = risk.max(validated.risk);
        management |= validated.contains_management();
        items.push(BatchItem::new(value, validated));
    }
    raw_change::authorize(server, (&identity, &host), (risk, input.confirm))?;
    let result = raw_change::run(server, (&host, &identity, management), async |changes| {
        changes
            .apply_batch(BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::RawRci,
                json!({ "validated": true }),
            ))
            .await
            .map_err(map_workflow)
    })
    .await?;
    let responses = result
        .responses
        .into_iter()
        .map(|response| match response {
            Ok(response) => {
                json!({ "ok": true, "value": response.value, "statuses": statuses(&response) })
            }
            Err(error) => json!({ "ok": false, "error": map_rci(&error).code() }),
        })
        .collect::<Vec<_>>();
    Ok(batch_applied(
        responses,
        result.unsaved,
        result.persists_immediately,
        result.persisted_paths,
    ))
}

/// Validates and applies one CLI line without saving.
// NOT cancel-safe: transmission can precede the workflow audit receipt and timer cleanup.
pub(crate) async fn cli_parse(server: &KccMcp, input: CliInput) -> Result<Value, McpFailure> {
    valid_host(&input.host)?;
    valid_text(&input.line, MAX_LINE_CHARS)?;
    let (identity, host) = server.authorize_host(Permission::RawRci, input.host)?;
    let mut raw_authorization = RawAuthorization::default();
    raw_authorization.raw_rci = identity.role.grants(Permission::RawRci);
    raw_authorization.admin_manage_routers = identity.role.grants(Permission::ManageRouters);
    let preliminary =
        preliminary_risk(|catalog| catalog.validate_cli(&input.line, raw_authorization))?;
    raw_change::authorize(server, (&identity, &host), (preliminary, input.confirm))?;
    let catalog = server.catalog(host.as_str()).await?;
    let validated = catalog
        .validate_cli(&input.line, raw_authorization)
        .map_err(|issues| {
            tracing::warn!(host = host.as_str(), ?issues, "MCP CLI validation failed");
            McpFailure::ValidationFailed
        })?;
    if validated.unvalidated {
        authorize_routers(
            &identity,
            Permission::ManageRouters,
            core::slice::from_ref(&host),
        )?;
    }
    raw_change::authorize(
        server,
        (&identity, &host),
        (validated.risk.max(preliminary), input.confirm),
    )?;
    let persistence = (
        validated.persists_immediately,
        validated.persisted_paths.clone(),
    );
    let result = raw_change::run(
        server,
        (&host, &identity, validated.contains_management()),
        async |changes| {
            changes
                .apply_cli(CliChangeRequest::new(
                    vec![ValidatedCli::new(input.line, validated)],
                    Vec::new(),
                    Permission::RawRci,
                    json!({ "validated": true }),
                ))
                .await
                .map_err(map_workflow)
        },
    )
    .await?;
    Ok(cli_applied(result.responses, result.unsaved, persistence))
}
