//! MCP server exposing catalog-validated router control to AI agents.
#![expect(
    clippy::absolute_paths,
    clippy::arithmetic_side_effects,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::multiple_inherent_impl,
    clippy::needless_pass_by_value,
    clippy::shadow_reuse,
    clippy::too_many_arguments,
    reason = "RMCP adapters contain schema-only private types and macro-mandated handler shapes; bounded pagination and owned deserialization are explicit protocol boundaries"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private RMCP schema carriers and dispatch helpers are described by their exported JSON schemas and tool metadata"
    )
)]
extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::JobRunner,
    permissions::{Permission, Role, ToolSpec, rbac_config},
    poller::Poller,
    registry::{RouterRegistry, authorize, scope_matches},
    settings::{McpConfig, PrivacyConfig},
    workflow::{
        BatchChangeRequest, BatchItem, ChangeRequest, ChangeWorkflow, CliChangeRequest,
        CliCommand as ValidatedCli, DeleteRequest, WorkflowError,
    },
};
use kcc_catalog::{Catalog, HttpMethod, RawAuthorization, Risk};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciBody, RciError, RciPath, capabilities::SupportTier};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResponse, GetPromptResult,
        ListPromptsResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams, Prompt,
        PromptMessage, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
        Resource, ResourceContents, Role as McpRole, ServerCapabilities, ServerConfig,
    },
    service::{RequestContext, RoleServer},
    tool, tool_handler, tool_router,
};
use rmcp_server_kit::rbac::{RbacConfig, current_identity, current_role};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_HOST_CHARS: usize = 32;
const MAX_PATH_CHARS: usize = 512;
const MAX_QUERY_CHARS: usize = 256;
const MAX_LINE_CHARS: usize = 2048;
const MAX_FIELDS: usize = 64;
const MAX_BATCH_ITEMS: usize = 64;
const MAX_RESULT_BYTES_HARD: usize = 8 * 1024 * 1024;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// A validated router profile id used by shared multi-router authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RouterId(String);

impl RouterId {
    /// Validates and constructs a router id.
    ///
    /// # Errors
    ///
    /// Returns `invalid_arguments` when the id is not a lowercase profile slug.
    #[inline]
    pub fn new(value: String) -> Result<Self, McpFailure> {
        valid_host(&value)?;
        Ok(Self(value))
    }

    /// Returns the router profile id.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Request identity resolved to one application role.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct McpIdentity {
    /// Stable authenticated identity name.
    pub name: String,
    /// Application role used for fine-grained authorization.
    pub role: Role,
}

impl McpIdentity {
    /// Creates a resolved identity.
    #[inline]
    #[must_use]
    pub const fn new(name: String, role: Role) -> Self {
        Self { name, role }
    }
}

/// Authorizes one permission for every router in an atomic multi-router operation.
///
/// # Errors
///
/// Returns the first registry authorization denial.
#[inline]
pub fn authorize_routers(
    identity: &McpIdentity,
    permission: Permission,
    routers: &[RouterId],
) -> Result<(), McpFailure> {
    for router in routers {
        authorize(&identity.role, permission, router.as_str()).map_err(|error| {
            tracing::warn!(
                identity = %identity.name,
                router = router.as_str(),
                error = ?error,
                "MCP router authorization denied"
            );
            McpFailure::Forbidden
        })?;
    }
    Ok(())
}

/// Stable errors exposed by the MCP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum McpFailure {
    /// Tool arguments failed boundary validation.
    InvalidArguments,
    /// Application permission or router scope denied the operation.
    Forbidden,
    /// The router could not be reached.
    RouterUnreachable,
    /// The router rejected an otherwise valid request.
    RouterRejected,
    /// Catalog or read-back validation failed.
    ValidationFailed,
    /// Concurrent state made the operation unsafe.
    Conflict,
    /// An internal service failed.
    Internal,
}

impl McpFailure {
    /// Stable wire code.
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::Forbidden => "forbidden",
            Self::RouterUnreachable => "router_unreachable",
            Self::RouterRejected => "router_rejected",
            Self::ValidationFailed => "validation_failed",
            Self::Conflict => "conflict",
            Self::Internal => "internal",
        }
    }
}

/// Application services and filtered RMCP tool dispatch.
#[derive(Clone)]
#[non_exhaustive]
pub struct KccMcp {
    config: McpConfig,
    privacy: PrivacyConfig,
    registry: Arc<RouterRegistry>,
    workflow: Arc<ChangeWorkflow>,
    jobs: Arc<JobRunner>,
    poller: Arc<Poller>,
    roles: Arc<[Role]>,
    fallback_role: Role,
    tool_router: ToolRouter<Self>,
    tool_specs: Arc<[ToolSpec]>,
    pseudonyms: Arc<Mutex<BTreeMap<String, String>>>,
}

impl fmt::Debug for KccMcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KccMcp")
            .field("config", &self.config)
            .field("privacy", &self.privacy)
            .field("registry", &self.registry)
            .field("workflow", &self.workflow)
            .field("jobs", &self.jobs)
            .field("poller", &self.poller)
            .field("roles", &self.roles)
            .field("fallback_role", &self.fallback_role)
            .field("tool_specs", &self.tool_specs)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HostInput {
    host: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListInput {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
    #[serde(default)]
    fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CatalogSearchInput {
    host: String,
    query: String,
    #[serde(default)]
    limit: Option<u16>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CatalogDescribeInput {
    host: String,
    path: String,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ReadKind {
    Get,
    ShowRc,
    ShowSc,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RciReadInput {
    host: String,
    catalog_path: String,
    path: Vec<String>,
    #[serde(default = "empty_object")]
    value: Value,
    #[serde(default = "default_read_kind")]
    kind: ReadKind,
    #[serde(default)]
    fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RciWriteInput {
    host: String,
    catalog_path: String,
    path: Vec<String>,
    #[serde(default = "empty_object")]
    value: Value,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RciBatchInput {
    host: String,
    items: Vec<Value>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CliInput {
    host: String,
    line: String,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct JobInput {
    id: String,
}

#[tool_router]
impl KccMcp {
    /// Builds a handler with toolsets and safety mode applied to both list and dispatch.
    #[inline]
    #[must_use]
    pub fn new(
        config: McpConfig,
        privacy: PrivacyConfig,
        registry: Arc<RouterRegistry>,
        workflow: Arc<ChangeWorkflow>,
        jobs: Arc<JobRunner>,
        poller: Arc<Poller>,
        roles: Vec<Role>,
        fallback_role: Role,
    ) -> Self {
        let definitions = tool_definitions();
        let mut tool_router = Self::tool_router();
        for definition in definitions {
            if !enabled(definition, &config) {
                tool_router.remove_route(definition.name);
            }
        }
        let tool_specs: Vec<ToolSpec> = definitions
            .iter()
            .filter(|definition| enabled(definition, &config))
            .map(|definition| {
                ToolSpec::new(
                    definition.name.to_owned(),
                    definition.permission,
                    Some(annotation_value(definition)),
                )
            })
            .collect();
        Self {
            config,
            privacy,
            registry,
            workflow,
            jobs,
            poller,
            roles: roles.into(),
            fallback_role,
            tool_router,
            tool_specs: tool_specs.into(),
            pseudonyms: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Returns the exact tool registry fed to application RBAC.
    #[inline]
    #[must_use]
    pub fn tool_specs(&self) -> &[ToolSpec] {
        &self.tool_specs
    }

    /// Builds the kit's coarse RBAC configuration from the active tools.
    #[inline]
    #[must_use]
    pub fn rbac_config(&self) -> RbacConfig {
        rbac_config(&self.roles, &self.tool_specs)
    }

    #[tool(
        name = "kcc_routers_list",
        description = "List authorized router profiles",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn routers_list(&self, Parameters(input): Parameters<ListInput>) -> CallToolResult {
        self.finish(self.routers_list_value(input))
    }

    #[tool(
        name = "kcc_router_info",
        description = "Read router identity, firmware, capabilities, and support tier",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn router_info(&self, Parameters(input): Parameters<HostInput>) -> CallToolResult {
        self.finish(self.router_info_value(input).await)
    }

    #[tool(
        name = "kcc_catalog_search",
        description = "Search commands available on a router",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn catalog_search(
        &self,
        Parameters(input): Parameters<CatalogSearchInput>,
    ) -> CallToolResult {
        self.finish(self.catalog_search_value(input).await)
    }

    #[tool(
        name = "kcc_catalog_describe",
        description = "Return the JSON Schema for one router command",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn catalog_describe(
        &self,
        Parameters(input): Parameters<CatalogDescribeInput>,
    ) -> CallToolResult {
        self.finish(self.catalog_describe_value(input).await)
    }

    #[tool(
        name = "kcc_rci_read",
        description = "Run a catalog-validated read-only RCI request",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn rci_read(&self, Parameters(input): Parameters<RciReadInput>) -> CallToolResult {
        self.finish(self.rci_read_value(input).await)
    }

    #[tool(
        name = "kcc_rci_execute",
        description = "Apply a catalog-validated raw RCI mutation without saving",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn rci_execute(&self, Parameters(input): Parameters<RciWriteInput>) -> CallToolResult {
        self.finish(self.rci_execute_value(input).await)
    }

    #[tool(
        name = "kcc_rci_delete",
        description = "Apply a catalog-validated RCI deletion without saving",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn rci_delete(&self, Parameters(input): Parameters<RciWriteInput>) -> CallToolResult {
        self.finish(self.rci_delete_value(input).await)
    }

    #[tool(
        name = "kcc_rci_batch",
        description = "Apply catalog-validated root RCI mutations without saving",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn rci_batch(&self, Parameters(input): Parameters<RciBatchInput>) -> CallToolResult {
        self.finish(self.rci_batch_value(input).await)
    }

    #[tool(
        name = "kcc_cli_parse",
        description = "Validate and apply one router CLI line without saving",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn cli_parse(&self, Parameters(input): Parameters<CliInput>) -> CallToolResult {
        self.finish(self.cli_parse_value(input).await)
    }

    #[tool(
        name = "kcc_job_status",
        description = "Read a background job status",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn job_status(&self, Parameters(input): Parameters<JobInput>) -> CallToolResult {
        self.finish(self.job_status_value(input))
    }

    #[tool(
        name = "kcc_job_cancel",
        description = "Cancel a running background job",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn job_cancel(&self, Parameters(input): Parameters<JobInput>) -> CallToolResult {
        self.finish(self.job_cancel_value(input).await)
    }

    #[tool(
        name = "kcc_config_state",
        description = "Read running configuration save and fail-safe state",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn config_state(&self, Parameters(input): Parameters<HostInput>) -> CallToolResult {
        self.finish(self.config_state_value(input).await)
    }

    #[tool(
        name = "kcc_config_save",
        description = "Explicitly save the router running configuration",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn config_save(&self, Parameters(input): Parameters<HostInput>) -> CallToolResult {
        self.finish(self.config_save_value(input).await)
    }
}

#[tool_handler(router = self.tool_router.clone())]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "async is generated by the rmcp ServerHandler tool dispatch macro"
)]
impl ServerHandler for KccMcp {
    #[inline]
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(
            self.visible_tools(current_identity().is_some()),
        ))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let identity = self.identity().map_err(failure_error)?;
        let resources = self
            .registry
            .list()
            .map_err(|error| internal_error("resources/list", &error))?
            .into_iter()
            .filter(|entry| authorize(&identity.role, Permission::Read, &entry.profile.id).is_ok())
            .map(|entry| {
                Resource::new(
                    format!("kcc://router/{}/snapshot", entry.profile.id),
                    format!("{} snapshot", entry.profile.id),
                )
                .with_mime_type("application/json")
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let identity = self.identity().map_err(failure_error)?;
        let uri = request.uri;
        if let Some(host) = uri
            .strip_prefix("kcc://router/")
            .and_then(|rest| rest.strip_suffix("/snapshot"))
        {
            valid_host(host).map_err(failure_error)?;
            authorize(&identity.role, Permission::Read, host)
                .map_err(|_error| failure_error(McpFailure::Forbidden))?;
            let mut receiver = self.poller.subscribe(host).await;
            if receiver.borrow().is_none() {
                receiver
                    .changed()
                    .await
                    .map_err(|error| internal_error("resources/read", &error))?;
            }
            let result = receiver
                .borrow()
                .clone()
                .ok_or_else(|| failure_error(McpFailure::RouterUnreachable))?
                .map_err(|error| internal_error("resources/read", &error))?;
            let value = json!({
                "host": host,
                "system": result.system,
                "internet": result.internet,
                "interfaces": result.interfaces_summary,
                "clients_count": result.clients_count,
                "wifi": result.wifi_summary,
                "last_change": result.last_change,
                "fetched_at": result.fetched_at
            });
            let text = self.shape(value, None).map_err(failure_error)?;
            return Ok(ReadResourceResult::new(vec![
                ResourceContents::text(text, uri).with_mime_type("application/json"),
            ])
            .into());
        }
        if let Some(rest) = uri.strip_prefix("kcc://catalog/") {
            let (version, path) = rest
                .split_once('/')
                .ok_or_else(|| failure_error(McpFailure::InvalidArguments))?;
            let catalog = catalog_for_version(version).map_err(failure_error)?;
            let decoded = path.replace("%20", " ");
            valid_text(&decoded, MAX_PATH_CHARS).map_err(failure_error)?;
            let command = catalog
                .lookup(&decoded)
                .ok_or_else(|| failure_error(McpFailure::InvalidArguments))?;
            let value = json!({
                "version": version,
                "path": command.path,
                "kind": format!("{:?}", command.kind).to_ascii_lowercase(),
                "prefix_no": command.prefix_no,
                "schema": catalog.to_json_schema(&decoded)
            });
            let text = self.shape(value, None).map_err(failure_error)?;
            return Ok(ReadResourceResult::new(vec![
                ResourceContents::text(text, uri).with_mime_type("application/json"),
            ])
            .into());
        }
        Err(failure_error(McpFailure::InvalidArguments))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(
            prompt_definitions()
                .iter()
                .map(|definition| Prompt::new(definition.name, Some(definition.description), None))
                .collect(),
        ))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let definition = prompt_definitions()
            .iter()
            .find(|definition| definition.name == request.name)
            .ok_or_else(|| failure_error(McpFailure::InvalidArguments))?;
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            McpRole::User,
            tr(Locale::En, definition.key, None),
        )])
        .into())
    }
}

impl KccMcp {
    fn visible_tools(&self, http_identity: bool) -> Vec<rmcp::model::Tool> {
        let mut tools = self.tool_router.list_all();
        if !http_identity {
            tools.retain(|tool| {
                self.tool_specs
                    .iter()
                    .find(|spec| spec.name == tool.name)
                    .is_some_and(|spec| self.fallback_role.grants(spec.permission))
            });
        }
        tools
    }

    fn identity(&self) -> Result<McpIdentity, McpFailure> {
        let role = match current_role() {
            Some(name) => self
                .roles
                .iter()
                .find(|role| role.name == name)
                .cloned()
                .ok_or(McpFailure::Forbidden)?,
            None => self.fallback_role.clone(),
        };
        Ok(McpIdentity::new(
            current_identity().unwrap_or_else(|| "stdio".to_owned()),
            role,
        ))
    }

    fn authorize_host(
        &self,
        permission: Permission,
        host: String,
    ) -> Result<(McpIdentity, RouterId), McpFailure> {
        let router = RouterId::new(host)?;
        let identity = self.identity()?;
        authorize_routers(&identity, permission, core::slice::from_ref(&router))?;
        Ok((identity, router))
    }

    async fn catalog(&self, host: &str) -> Result<Catalog, McpFailure> {
        let info = self.registry.poll_info(host).await.map_err(|error| {
            tracing::warn!(host, error = ?error, "MCP router capability detection failed");
            McpFailure::RouterUnreachable
        })?;
        Catalog::for_router(&info).map_err(|error| {
            tracing::warn!(host, error = ?error, "MCP catalog selection failed");
            McpFailure::ValidationFailed
        })
    }

    async fn begin_change(
        &self,
        host: &RouterId,
        identity: &McpIdentity,
    ) -> Result<kcc_app::workflow::ChangeSet, McpFailure> {
        self.workflow
            .begin(
                host.as_str(),
                Actor::new(ActorKind::Mcp, identity.name.clone()),
                &identity.role,
                None,
                false,
            )
            .await
            .map_err(map_workflow)
    }

    fn routers_list_value(&self, input: ListInput) -> Result<Value, McpFailure> {
        validate_list(&input)?;
        let identity = self.identity()?;
        let mut items = self
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

    async fn router_info_value(&self, input: HostInput) -> Result<Value, McpFailure> {
        let (_identity, host) = self.authorize_host(Permission::Read, input.host)?;
        let info = self
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
            "brand": format!("{:?}", info.brand).to_ascii_lowercase(),
            "components": info.components,
            "features": info.features,
            "support_tier": support_tier
        }))
    }

    async fn catalog_search_value(&self, input: CatalogSearchInput) -> Result<Value, McpFailure> {
        valid_text(&input.query, MAX_QUERY_CHARS)?;
        validate_fields(input.fields.as_deref())?;
        let (_identity, host) = self.authorize_host(Permission::Read, input.host)?;
        let catalog = self.catalog(host.as_str()).await?;
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

    async fn catalog_describe_value(
        &self,
        input: CatalogDescribeInput,
    ) -> Result<Value, McpFailure> {
        valid_text(&input.path, MAX_PATH_CHARS)?;
        let (_identity, host) = self.authorize_host(Permission::Read, input.host)?;
        let catalog = self.catalog(host.as_str()).await?;
        let schema = catalog
            .to_json_schema(&input.path)
            .ok_or(McpFailure::ValidationFailed)?;
        Ok(json!({ "path": input.path, "schema": schema }))
    }

    async fn rci_read_value(&self, input: RciReadInput) -> Result<Value, McpFailure> {
        validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
        validate_fields(input.fields.as_deref())?;
        let (_identity, host) = self.authorize_host(Permission::Read, input.host)?;
        let catalog = self.catalog(host.as_str()).await?;
        let method = match input.kind {
            ReadKind::Get => HttpMethod::Get,
            ReadKind::ShowRc | ReadKind::ShowSc => HttpMethod::Post,
        };
        let _validated = catalog
            .validate(&input.catalog_path, method, &input.value)
            .map_err(|issues| {
                tracing::warn!(
                    host = host.as_str(),
                    ?issues,
                    "MCP RCI read validation failed"
                );
                McpFailure::ValidationFailed
            })?;
        let client = self.registry.client(host.as_str()).await.map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP RCI client failed");
            McpFailure::RouterUnreachable
        })?;
        let body = match input.kind {
            ReadKind::Get => {
                let path = RciPath::from_segments(&input.path)
                    .map_err(|_error| McpFailure::InvalidArguments)?;
                client.show(&path, &input.value).await
            }
            ReadKind::ShowRc => client.show_rc(input.value).await,
            ReadKind::ShowSc => client.show_sc(input.value).await,
        }
        .map_err(|error| map_rci(&error))?;
        Ok(rci_body_value(body))
    }

    async fn rci_execute_value(&self, input: RciWriteInput) -> Result<Value, McpFailure> {
        validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
        let (identity, host) = self.authorize_host(Permission::RawRci, input.host)?;
        let preliminary = catalog_for_version("5.1")?
            .validate(&input.catalog_path, HttpMethod::Post, &input.value)
            .map_err(|issues| {
                tracing::warn!(
                    host = host.as_str(),
                    ?issues,
                    "MCP RCI execute validation failed"
                );
                McpFailure::ValidationFailed
            })?;
        self.require_destructive(preliminary.risk, input.confirm)?;
        let catalog = self.catalog(host.as_str()).await?;
        let validated = catalog
            .validate(&input.catalog_path, HttpMethod::Post, &input.value)
            .map_err(|issues| {
                tracing::warn!(
                    host = host.as_str(),
                    ?issues,
                    "MCP RCI execute validation failed"
                );
                McpFailure::ValidationFailed
            })?;
        self.require_destructive(validated.risk, input.confirm)?;
        let mut changes = self.begin_change(&host, &identity).await?;
        let result = changes
            .apply(ChangeRequest::new(
                input.catalog_path,
                input.path,
                input.value,
                Vec::new(),
                Permission::RawRci,
                json!({ "validated": true }),
            ))
            .await
            .map_err(map_workflow)?;
        Ok(json!({ "statuses": [], "unsaved": result.unsaved }))
    }

    async fn rci_delete_value(&self, input: RciWriteInput) -> Result<Value, McpFailure> {
        validate_rci_input(&input.host, &input.catalog_path, &input.path, &input.value)?;
        let (identity, host) = self.authorize_host(Permission::RawRci, input.host)?;
        let preliminary = catalog_for_version("5.1")?
            .validate(&input.catalog_path, HttpMethod::Delete, &input.value)
            .map_err(|issues| {
                tracing::warn!(
                    host = host.as_str(),
                    ?issues,
                    "MCP RCI delete validation failed"
                );
                McpFailure::ValidationFailed
            })?;
        self.require_destructive(preliminary.risk.max(Risk::Destructive), input.confirm)?;
        let catalog = self.catalog(host.as_str()).await?;
        let validated = catalog
            .validate(&input.catalog_path, HttpMethod::Delete, &input.value)
            .map_err(|issues| {
                tracing::warn!(
                    host = host.as_str(),
                    ?issues,
                    "MCP RCI delete validation failed"
                );
                McpFailure::ValidationFailed
            })?;
        self.require_destructive(validated.risk.max(Risk::Destructive), input.confirm)?;
        let mut changes = self.begin_change(&host, &identity).await?;
        let result = changes
            .apply_delete(DeleteRequest::new(
                input.catalog_path,
                input.path,
                input.value,
                Vec::new(),
                Permission::RawRci,
                json!({ "validated": true }),
            ))
            .await
            .map_err(map_workflow)?;
        Ok(json!({ "statuses": [], "unsaved": result.unsaved }))
    }

    async fn rci_batch_value(&self, input: RciBatchInput) -> Result<Value, McpFailure> {
        valid_host(&input.host)?;
        if input.items.is_empty() || input.items.len() > MAX_BATCH_ITEMS {
            return Err(McpFailure::InvalidArguments);
        }
        let (identity, host) = self.authorize_host(Permission::RawRci, input.host)?;
        let catalog = self.catalog(host.as_str()).await?;
        let mut risk = Risk::Read;
        let mut items = Vec::with_capacity(input.items.len());
        for value in input.items {
            valid_value_size(&value)?;
            let validated = catalog
                .validate("", HttpMethod::Post, &value)
                .map_err(|issues| {
                    tracing::warn!(
                        host = host.as_str(),
                        ?issues,
                        "MCP RCI batch validation failed"
                    );
                    McpFailure::ValidationFailed
                })?;
            risk = risk.max(validated.risk);
            items.push(BatchItem::new(value, validated));
        }
        self.require_destructive(risk, input.confirm)?;
        let mut changes = self.begin_change(&host, &identity).await?;
        let result = changes
            .apply_batch(BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::RawRci,
                json!({ "validated": true }),
            ))
            .await
            .map_err(map_workflow)?;
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
        Ok(json!({ "responses": responses, "unsaved": result.unsaved }))
    }

    async fn cli_parse_value(&self, input: CliInput) -> Result<Value, McpFailure> {
        valid_host(&input.host)?;
        valid_text(&input.line, MAX_LINE_CHARS)?;
        let (identity, host) = self.authorize_host(Permission::RawRci, input.host)?;
        let catalog = self.catalog(host.as_str()).await?;
        let mut raw_authorization = RawAuthorization::default();
        raw_authorization.raw_rci = identity.role.grants(Permission::RawRci);
        raw_authorization.admin_manage_routers = identity.role.grants(Permission::ManageRouters);
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
        self.require_destructive(validated.risk, input.confirm)?;
        let mut changes = self.begin_change(&host, &identity).await?;
        let result = changes
            .apply_cli(CliChangeRequest::new(
                vec![ValidatedCli::new(input.line, validated)],
                Vec::new(),
                Permission::RawRci,
                json!({ "validated": true }),
            ))
            .await
            .map_err(map_workflow)?;
        Ok(json!({
            "responses": result.responses.into_iter().map(rci_body_value).collect::<Vec<_>>(),
            "unsaved": result.unsaved
        }))
    }

    fn job_status_value(&self, input: JobInput) -> Result<Value, McpFailure> {
        valid_job_id(&input.id)?;
        let identity = self.identity()?;
        let record = self.jobs.get(&input.id).map_err(|error| {
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

    async fn job_cancel_value(&self, input: JobInput) -> Result<Value, McpFailure> {
        valid_job_id(&input.id)?;
        let identity = self.identity()?;
        let record = self.jobs.get(&input.id).map_err(|error| {
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
        self.jobs.cancel(&input.id).await.map_err(|error| {
            tracing::warn!(job = input.id, error = ?error, "MCP job cancellation failed");
            McpFailure::Conflict
        })?;
        Ok(json!({ "cancelled": true }))
    }

    async fn config_state_value(&self, input: HostInput) -> Result<Value, McpFailure> {
        let (_identity, host) = self.authorize_host(Permission::Read, input.host)?;
        let client = self.registry.client(host.as_str()).await.map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP config state client failed");
            McpFailure::RouterUnreachable
        })?;
        let path = RciPath::from_segments(["show", "last-change"])
            .map_err(|_error| McpFailure::Internal)?;
        client
            .show(&path, &())
            .await
            .map(rci_body_value)
            .map_err(|error| map_rci(&error))
    }

    async fn config_save_value(&self, input: HostInput) -> Result<Value, McpFailure> {
        let (identity, host) = self.authorize_host(Permission::Save, input.host)?;
        let mut changes = self.begin_change(&host, &identity).await?;
        changes.save().await.map_err(map_workflow)?;
        Ok(json!({ "saved": true, "unsaved": false }))
    }

    fn require_destructive(&self, risk: Risk, confirm: bool) -> Result<(), McpFailure> {
        if risk == Risk::Destructive && (!confirm || !self.config.allow_destructive) {
            return Err(McpFailure::Forbidden);
        }
        Ok(())
    }

    fn finish(&self, result: Result<Value, McpFailure>) -> CallToolResult {
        let request_id = format!("mcp-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
        match result.and_then(|value| self.shape(value, Some(&request_id))) {
            Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
            Err(error) => {
                tracing::warn!(request_id, code = error.code(), "MCP tool request failed");
                let text = serde_json::to_string(&json!({
                    "error": error.code(),
                    "request_id": request_id
                }))
                .unwrap_or_else(|_error| "{\"error\":\"internal\"}".to_owned());
                CallToolResult::error(vec![ContentBlock::text(text)])
            }
        }
    }

    fn shape(&self, mut value: Value, request_id: Option<&str>) -> Result<String, McpFailure> {
        redact_secrets(&mut value);
        if self.privacy.redact_clients_in_mcp {
            let mut pseudonyms = self
                .pseudonyms
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            pseudonymize(&mut value, &mut pseudonyms, None);
        }
        let fields = value.get("fields").and_then(Value::as_array).map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        if let Some(selected) = fields {
            project(&mut value, &selected);
        }
        let encoded = serde_json::to_string(&value).map_err(|error| {
            tracing::error!(error = ?error, "MCP result serialization failed");
            McpFailure::Internal
        })?;
        let cap = usize::try_from(self.config.max_result_bytes)
            .unwrap_or(usize::MAX)
            .min(MAX_RESULT_BYTES_HARD);
        if encoded.len() <= cap {
            return Ok(encoded);
        }
        let truncated = json!({
            "truncated": true,
            "next_cursor": "1",
            "request_id": request_id
        });
        let fallback = serde_json::to_string(&truncated).map_err(|_error| McpFailure::Internal)?;
        if fallback.len() > cap {
            return Err(McpFailure::Internal);
        }
        Ok(fallback)
    }
}

#[derive(Clone, Copy)]
struct ToolDefinition {
    name: &'static str,
    permission: Permission,
    toolset: &'static str,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
}

static TOOL_DEFINITIONS: [ToolDefinition; 13] = [
    tool_definition(
        "kcc_routers_list",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition(
        "kcc_router_info",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition(
        "kcc_catalog_search",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition(
        "kcc_catalog_describe",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition("kcc_rci_read", Permission::Read, "core", true, false, true),
    tool_definition(
        "kcc_job_status",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition(
        "kcc_job_cancel",
        Permission::Write,
        "core",
        false,
        false,
        true,
    ),
    tool_definition(
        "kcc_config_state",
        Permission::Read,
        "core",
        true,
        false,
        true,
    ),
    tool_definition(
        "kcc_config_save",
        Permission::Save,
        "core",
        false,
        false,
        true,
    ),
    tool_definition(
        "kcc_rci_execute",
        Permission::RawRci,
        "raw",
        false,
        true,
        false,
    ),
    tool_definition(
        "kcc_rci_delete",
        Permission::RawRci,
        "raw",
        false,
        true,
        true,
    ),
    tool_definition(
        "kcc_rci_batch",
        Permission::RawRci,
        "raw",
        false,
        true,
        false,
    ),
    tool_definition(
        "kcc_cli_parse",
        Permission::RawRci,
        "raw",
        false,
        true,
        false,
    ),
];

const fn tool_definitions() -> &'static [ToolDefinition] {
    &TOOL_DEFINITIONS
}

const fn tool_definition(
    name: &'static str,
    permission: Permission,
    toolset: &'static str,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
) -> ToolDefinition {
    ToolDefinition {
        name,
        permission,
        toolset,
        read_only,
        destructive,
        idempotent,
    }
}

fn enabled(definition: &ToolDefinition, config: &McpConfig) -> bool {
    config
        .toolsets
        .iter()
        .any(|toolset| toolset == definition.toolset)
        && (!config.read_only || definition.read_only)
}

fn annotation_value(definition: &ToolDefinition) -> Value {
    json!({
        "readOnlyHint": definition.read_only,
        "destructiveHint": definition.destructive,
        "idempotentHint": definition.idempotent,
        "openWorldHint": false
    })
}

struct PromptDefinition {
    name: &'static str,
    description: &'static str,
    key: kcc_i18n::bundle::MessageKey,
}

const fn prompt_definitions() -> &'static [PromptDefinition] {
    &[
        PromptDefinition {
            name: "troubleshoot_internet",
            description: "Safely diagnose internet connectivity",
            key: keys::MCP_PROMPT_TROUBLESHOOT_INTERNET,
        },
        PromptDefinition {
            name: "troubleshoot_wifi",
            description: "Safely diagnose Wi-Fi connectivity",
            key: keys::MCP_PROMPT_TROUBLESHOOT_WIFI,
        },
        PromptDefinition {
            name: "troubleshoot_device",
            description: "Safely diagnose one client device",
            key: keys::MCP_PROMPT_TROUBLESHOOT_DEVICE,
        },
        PromptDefinition {
            name: "safe_change_workflow",
            description: "Plan, apply, verify, and explicitly save a safe change",
            key: keys::MCP_PROMPT_SAFE_CHANGE_WORKFLOW,
        },
    ]
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

const fn default_read_kind() -> ReadKind {
    ReadKind::Get
}

fn valid_host(host: &str) -> Result<(), McpFailure> {
    if !(1..=MAX_HOST_CHARS).contains(&host.len())
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

fn valid_text(value: &str, max_chars: usize) -> Result<(), McpFailure> {
    let length = value.chars().count();
    if !(1..=max_chars).contains(&length) || value.chars().any(char::is_control) {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

fn valid_job_id(id: &str) -> Result<(), McpFailure> {
    if id.len() > 64
        || id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

fn validate_rci_input(
    host: &str,
    catalog_path: &str,
    path: &[String],
    value: &Value,
) -> Result<(), McpFailure> {
    valid_host(host)?;
    valid_text(catalog_path, MAX_PATH_CHARS)?;
    if path.is_empty() || path.len() > 16 {
        return Err(McpFailure::InvalidArguments);
    }
    for segment in path {
        valid_text(segment, 64)?;
    }
    valid_value_size(value)
}

fn valid_value_size(value: &Value) -> Result<(), McpFailure> {
    let bytes = serde_json::to_vec(value).map_err(|_error| McpFailure::InvalidArguments)?;
    if bytes.len() > 900 * 1024 {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(())
}

fn validate_list(input: &ListInput) -> Result<(), McpFailure> {
    let _offset = parse_cursor(input.cursor.as_deref())?;
    validate_fields(input.fields.as_deref())
}

fn validate_fields(fields: Option<&[String]>) -> Result<(), McpFailure> {
    let Some(fields) = fields else {
        return Ok(());
    };
    if fields.len() > MAX_FIELDS {
        return Err(McpFailure::InvalidArguments);
    }
    for field in fields {
        valid_text(field, 64)?;
    }
    Ok(())
}

fn parse_cursor(cursor: Option<&str>) -> Result<usize, McpFailure> {
    cursor
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_error| McpFailure::InvalidArguments)
}

fn paginate(
    items: &mut Vec<Value>,
    cursor: Option<&str>,
    limit: Option<u16>,
) -> Result<(), McpFailure> {
    let offset = parse_cursor(cursor)?;
    let count = usize::from(limit.unwrap_or(50).min(100));
    if offset >= items.len() {
        items.clear();
    } else {
        drop(items.drain(..offset));
        items.truncate(count);
    }
    Ok(())
}

fn map_workflow(error: WorkflowError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP change workflow failed");
    match error {
        WorkflowError::PermissionDenied { router: _ } => McpFailure::Forbidden,
        WorkflowError::CatalogValidation { issues: _ }
        | WorkflowError::VerificationFailed { field: _ } => McpFailure::ValidationFailed,
        WorkflowError::Conflict { agent: _ } | WorkflowError::RouterBusy { actor: _ } => {
            McpFailure::Conflict
        }
        WorkflowError::Rci(rci) => map_rci(&rci),
        WorkflowError::State(_)
        | WorkflowError::Registry(_)
        | WorkflowError::Backup(_)
        | WorkflowError::Audit(_)
        | WorkflowError::InvalidResponse
        | WorkflowError::SaveTimeout
        | _ => McpFailure::Internal,
    }
}

fn map_rci(error: &RciError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP RCI request failed");
    match error {
        RciError::Transport | RciError::Timeout | RciError::Policy => McpFailure::RouterUnreachable,
        RciError::Auth(_)
        | RciError::Http { status: _ }
        | RciError::Rci {
            pointer: _,
            code: _,
            ident: _,
            message: _,
        }
        | RciError::NotFound
        | RciError::MethodNotAllowed => McpFailure::RouterRejected,
        RciError::Validation => McpFailure::ValidationFailed,
        RciError::BodyTooLarge | RciError::Decode | _ => McpFailure::Internal,
    }
}

fn rci_body_value(body: RciBody) -> Value {
    match body {
        RciBody::Json(response) => json!({
            "value": response.value,
            "statuses": statuses(&response)
        }),
        RciBody::Text(text) => json!({ "text": text, "statuses": [] }),
        _ => json!({ "error": "internal" }),
    }
}

fn statuses(response: &kcc_rci::RciResponse) -> Vec<Value> {
    response
        .statuses
        .iter()
        .map(|(pointer, item)| {
            json!({
                "pointer": pointer.as_str(),
                "level": format!("{:?}", item.status).to_ascii_lowercase(),
                "code": item.code,
                "ident": item.ident
            })
        })
        .collect()
}

fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let lowered = key.to_ascii_lowercase();
                if [
                    "password",
                    "passwd",
                    "token",
                    "secret",
                    "api_key",
                    "private_key",
                    "ns3",
                ]
                .iter()
                .any(|needle| lowered.contains(needle))
                {
                    *nested = Value::String("<redacted>".to_owned());
                } else {
                    redact_secrets(nested);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                redact_secrets(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn pseudonymize(
    value: &mut Value,
    pseudonyms: &mut BTreeMap<String, String>,
    parent_key: Option<&str>,
) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                pseudonymize(nested, pseudonyms, Some(key));
            }
        }
        Value::Array(values) => {
            for nested in values {
                pseudonymize(nested, pseudonyms, parent_key);
            }
        }
        Value::String(text) if client_identifier(parent_key, text) => {
            let next = pseudonyms.len().saturating_add(1);
            let replacement = pseudonyms
                .entry(text.clone())
                .or_insert_with(|| format!("client-{next}"))
                .clone();
            *text = replacement;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn client_identifier(parent_key: Option<&str>, value: &str) -> bool {
    let key_match = parent_key.is_some_and(|key| {
        let lowered = key.to_ascii_lowercase();
        ["mac", "hostname", "host_name", "ip", "address"]
            .iter()
            .any(|needle| lowered.contains(needle))
    });
    key_match || looks_like_mac(value)
}

fn looks_like_mac(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn project(value: &mut Value, fields: &[String]) {
    let Value::Object(object) = value else {
        return;
    };
    object.retain(|key, _nested| fields.contains(key));
}

fn catalog_for_version(version: &str) -> Result<Catalog, McpFailure> {
    use kcc_rci::version::{FirmwareVersion, Stage};

    let firmware = match version {
        "4.3" => FirmwareVersion::new(4, 3, Stage::Release, 0, 0),
        "5.0" => FirmwareVersion::new(5, 0, Stage::Release, 0, 0),
        "5.1" => FirmwareVersion::new(5, 1, Stage::Release, 0, 0),
        _ => return Err(McpFailure::InvalidArguments),
    };
    Catalog::for_firmware_and_model(firmware, None).map_err(|_error| McpFailure::Internal)
}

fn failure_error(failure: McpFailure) -> ErrorData {
    ErrorData::invalid_params(failure.code(), None)
}

fn internal_error(context: &str, error: &dyn fmt::Debug) -> ErrorData {
    tracing::error!(context, ?error, "MCP internal request failure");
    ErrorData::internal_error("internal", None)
}

#[cfg(test)]
#[expect(
    clippy::absolute_paths,
    clippy::assertions_on_result_states,
    clippy::default_trait_access,
    clippy::expect_used,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::std_instead_of_alloc,
    reason = "test fixtures use direct filesystem setup and assertions rather than public API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::sync::Arc;

    use kcc_app::{
        audit::AuditLog,
        backups::BackupStore,
        jobs::JobRunner,
        permissions::{Permission, Role},
        persist::StateStore,
        poller::Poller,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::{McpConfig, OutboundConfig, PrivacyConfig},
        workflow::ChangeWorkflow,
    };
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile};
    use proptest::{
        option,
        prelude::*,
        test_runner::{Config as ProptestConfig, TestCaseResult, TestRunner},
    };
    use rmcp::ServerHandler as _;
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use url::Url;

    use super::{
        KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers, pseudonymize,
        tool_definitions,
    };

    struct Fixture {
        directory: TempDir,
        server: KccMcp,
        handle: kcc_testkit::Handle,
    }

    impl Fixture {
        async fn spawn(config: McpConfig, privacy: PrivacyConfig) -> Result<Self, Box<dyn Error>> {
            Self::spawn_with_role(config, privacy, admin_role()).await
        }

        async fn spawn_with_role(
            config: McpConfig,
            privacy: PrivacyConfig,
            fallback_role: Role,
        ) -> Result<Self, Box<dyn Error>> {
            let directory = TempDir::new()?;
            let router = FakeRouter::builder(Profile::default()).build()?;
            let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
            let password = directory.path().join("password");
            std::fs::write(&password, DEFAULT_PASSWORD)?;
            let state = StateStore::open(&directory.path().join("state"))?;
            let mut outbound = OutboundConfig::default();
            outbound.allow_loopback = true;
            let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
            let admin = admin_role();
            registry
                .create(
                    &admin,
                    ManagedRouterProfile::new(
                        "lab-1".to_owned(),
                        Url::parse(&format!("http://{address}"))?,
                        "admin".to_owned(),
                        password,
                    ),
                )
                .await?;
            let backups = Arc::new(BackupStore::new(
                state.clone(),
                MasterKey::from_bytes([9_u8; 32]),
            ));
            let audit = AuditLog::spawn(&state)?;
            let workflow =
                ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit);
            let jobs = JobRunner::open(state, Arc::clone(&registry)).await?;
            let poller = Poller::new(Arc::clone(&registry));
            let roles = vec![admin, lab_role(), viewer_role(), operator_role()];
            let server = KccMcp::new(
                config,
                privacy,
                registry,
                workflow,
                jobs,
                poller,
                roles,
                fallback_role,
            );
            Ok(Self {
                directory,
                server,
                handle,
            })
        }

        async fn shutdown(self) -> Result<(), Box<dyn Error>> {
            let Self {
                directory,
                server: _,
                handle,
            } = self;
            handle.shutdown().await?;
            drop(directory);
            Ok(())
        }
    }

    fn admin_role() -> Role {
        Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
    }

    fn lab_role() -> Role {
        Role::new("lab".to_owned(), Permission::ALL, vec!["lab-*".to_owned()])
    }

    fn viewer_role() -> Role {
        Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        )
    }

    fn operator_role() -> Role {
        Role::new(
            "operator".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Save,
                Permission::Migrate,
            ],
            vec!["*".to_owned()],
        )
    }

    #[tokio::test]
    async fn fallback_role_filters_stdio_tools_without_changing_http_inventory()
    -> Result<(), Box<dyn Error>> {
        let viewer = Fixture::spawn_with_role(
            McpConfig::default(),
            PrivacyConfig::default(),
            viewer_role(),
        )
        .await?;
        let viewer_tools = viewer.server.visible_tools(false);
        assert!(viewer_tools.iter().all(|tool| {
            tool.annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint)
                == Some(true)
        }));
        assert!(
            !viewer_tools
                .iter()
                .any(|tool| tool.name == "kcc_config_save")
        );
        assert_eq!(
            viewer.server.visible_tools(true),
            viewer.server.tool_router.list_all(),
            "HTTP inventory remains unchanged for kit RBAC filtering"
        );
        viewer.shutdown().await?;

        let operator = Fixture::spawn_with_role(
            McpConfig::default(),
            PrivacyConfig::default(),
            operator_role(),
        )
        .await?;
        assert!(
            operator
                .server
                .visible_tools(false)
                .iter()
                .any(|tool| tool.name == "kcc_config_save")
        );
        operator.shutdown().await?;
        Ok(())
    }

    #[test]
    fn default_config_and_tool_registry_respect_caps() {
        let config = McpConfig::default();
        assert_eq!(config.max_result_bytes, 0x8000);
        let core_count = tool_definitions()
            .iter()
            .filter(|definition| definition.toolset == "core")
            .count();
        assert!(core_count <= 25);
        assert!(tool_definitions().len() <= 70);
    }

    #[test]
    fn multi_router_authorization_checks_every_router() -> Result<(), McpFailure> {
        let identity = McpIdentity::new("alice".to_owned(), lab_role());
        let prod = RouterId::new("prod-1".to_owned())?;
        let lab_one = RouterId::new("lab-1".to_owned())?;
        let lab_two = RouterId::new("lab-2".to_owned())?;
        assert_eq!(
            authorize_routers(&identity, Permission::Migrate, &[prod, lab_one.clone()]),
            Err(McpFailure::Forbidden)
        );
        assert!(authorize_routers(&identity, Permission::Migrate, &[lab_two, lab_one]).is_ok());
        Ok(())
    }

    #[test]
    fn client_redaction_hides_fixture_addresses() {
        let mut value = json!({
            "clients": [
                {"mac":"02:00:00:00:00:01","hostname":"phone","ip":"192.0.2.10"},
                {"mac":"02:00:00:00:00:02","hostname":"laptop","ip":"192.0.2.11"}
            ]
        });
        let mut pseudonyms = Default::default();
        pseudonymize(&mut value, &mut pseudonyms, None);
        let text = serde_json::to_string(&value).expect("JSON fixture serializes");
        for secret in [
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "phone",
            "laptop",
            "192.0.2.10",
            "192.0.2.11",
        ] {
            assert!(
                !text.contains(secret),
                "fixture identifier leaked: {secret}"
            );
        }
    }

    #[tokio::test]
    async fn tool_registration_obeys_default_and_read_only_modes() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(McpConfig::default(), PrivacyConfig::default()).await?;
        let tools = fixture.server.get_info();
        assert!(tools.capabilities.tools.is_some());
        assert!(fixture.server.tool_specs().len() <= 25);
        fixture.shutdown().await?;

        let mut config = McpConfig::default();
        config.read_only = true;
        config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
        let read_only = Fixture::spawn(config, PrivacyConfig::default()).await?;
        assert!(read_only.server.tool_specs().iter().all(|spec| {
            spec.annotations
                .as_ref()
                .and_then(|value| value.get("readOnlyHint"))
                .and_then(Value::as_bool)
                == Some(true)
        }));
        read_only.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn invalid_and_destructive_requests_never_reach_router() -> Result<(), Box<dyn Error>> {
        let mut config = McpConfig::default();
        config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
        let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
        let before = fixture.handle.request_count();
        let invalid = fixture
            .server
            .rci_execute_value(super::RciWriteInput {
                host: "lab-1".to_owned(),
                catalog_path: "system reboot".to_owned(),
                path: vec!["system".to_owned(), "reboot".to_owned()],
                value: json!({"unexpected":"incident"}),
                confirm: true,
            })
            .await;
        assert_eq!(invalid, Err(McpFailure::ValidationFailed));
        assert_eq!(fixture.handle.request_count(), before);

        assert_eq!(
            fixture
                .server
                .require_destructive(kcc_catalog::Risk::Destructive, true),
            Err(McpFailure::Forbidden)
        );
        fixture.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_result_returns_truncation_marker() -> Result<(), Box<dyn Error>> {
        let mut config = McpConfig::default();
        config.max_result_bytes = 96;
        let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
        let text = fixture
            .server
            .shape(json!({"value":"x".repeat(1024)}), Some("request"))
            .map_err(|error| format!("shape failed: {error:?}"))?;
        let value: Value = serde_json::from_str(&text)?;
        assert_eq!(value.get("truncated"), Some(&Value::Bool(true)));
        assert!(value.get("next_cursor").is_some());
        fixture.shutdown().await?;
        Ok(())
    }

    fn arbitrary_text() -> BoxedStrategy<String> {
        prop_oneof![
            any::<String>(),
            Just(String::new()),
            Just("lab-1".to_owned()),
            Just("\0control\n".to_owned()),
            Just("\u{440}\u{43e}\u{443}\u{442}\u{435}\u{440}-\u{1f680}".to_owned()),
            Just("x".repeat(2048)),
        ]
        .boxed()
    }

    fn arbitrary_json() -> BoxedStrategy<Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            arbitrary_text().prop_map(Value::String),
        ];
        leaf.prop_recursive(3, 32, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map(".{0,32}", inner, 0..6)
                    .prop_map(|items| Value::Object(items.into_iter().collect())),
            ]
        })
        .boxed()
    }

    fn arbitrary_fields() -> BoxedStrategy<Option<Vec<String>>> {
        option::of(prop::collection::vec(arbitrary_text(), 0..20)).boxed()
    }

    fn list_arguments() -> BoxedStrategy<Value> {
        let shaped = (
            option::of(arbitrary_text()),
            option::of(any::<u16>()),
            arbitrary_fields(),
        )
            .prop_map(|(cursor, limit, fields)| {
                json!({"cursor": cursor, "limit": limit, "fields": fields})
            });
        prop_oneof![
            6 => shaped,
            1 => arbitrary_json(),
            1 => Just(json!({"cursor": [], "unknown": true})),
        ]
        .boxed()
    }

    fn host_arguments() -> BoxedStrategy<Value> {
        prop_oneof![
            6 => arbitrary_text().prop_map(|host| json!({"host": host})),
            1 => arbitrary_json(),
            1 => Just(json!({})),
            1 => Just(json!({"host": 7, "unknown": true})),
        ]
        .boxed()
    }

    fn catalog_search_arguments() -> BoxedStrategy<Value> {
        let shaped = (
            arbitrary_text(),
            arbitrary_text(),
            option::of(any::<u16>()),
            option::of(arbitrary_text()),
            arbitrary_fields(),
        )
            .prop_map(|(host, query, limit, cursor, fields)| {
                json!({
                    "host": host,
                    "query": query,
                    "limit": limit,
                    "cursor": cursor,
                    "fields": fields
                })
            });
        prop_oneof![
            6 => shaped,
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1"})),
            1 => Just(json!({"host": [], "query": false})),
        ]
        .boxed()
    }

    fn catalog_describe_arguments() -> BoxedStrategy<Value> {
        prop_oneof![
            6 => (arbitrary_text(), arbitrary_text())
                .prop_map(|(host, path)| json!({"host": host, "path": path})),
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1"})),
            1 => Just(json!({"host": true, "path": []})),
        ]
        .boxed()
    }

    fn rci_read_arguments() -> BoxedStrategy<Value> {
        let shaped = (
            arbitrary_text(),
            arbitrary_text(),
            prop::collection::vec(arbitrary_text(), 0..20),
            arbitrary_json(),
            prop_oneof![Just("get"), Just("show_rc"), Just("show_sc")],
            arbitrary_fields(),
        )
            .prop_map(|(host, catalog_path, path, value, kind, fields)| {
                json!({
                    "host": host,
                    "catalog_path": catalog_path,
                    "path": path,
                    "value": value,
                    "kind": kind,
                    "fields": fields
                })
            });
        prop_oneof![
            6 => shaped,
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1", "catalog_path": "show version"})),
            1 => Just(json!({
                "host": [], "catalog_path": 1, "path": false, "kind": "other"
            })),
        ]
        .boxed()
    }

    fn rci_write_arguments() -> BoxedStrategy<Value> {
        let shaped = (
            arbitrary_text(),
            arbitrary_text(),
            prop::collection::vec(arbitrary_text(), 0..20),
            arbitrary_json(),
            any::<bool>(),
        )
            .prop_map(|(host, catalog_path, path, value, confirm)| {
                json!({
                    "host": host,
                    "catalog_path": catalog_path,
                    "path": path,
                    "value": value,
                    "confirm": confirm
                })
            });
        prop_oneof![
            6 => shaped,
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1", "path": []})),
            1 => Just(json!({
                "host": {}, "catalog_path": [], "path": "system", "confirm": 1
            })),
        ]
        .boxed()
    }

    fn rci_batch_arguments() -> BoxedStrategy<Value> {
        let shaped = (
            arbitrary_text(),
            prop::collection::vec(arbitrary_json(), 0..20),
            any::<bool>(),
        )
            .prop_map(
                |(host, items, confirm)| json!({"host": host, "items": items, "confirm": confirm}),
            );
        prop_oneof![
            6 => shaped,
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1"})),
            1 => Just(json!({"host": 1, "items": {}, "confirm": "yes"})),
        ]
        .boxed()
    }

    fn cli_arguments() -> BoxedStrategy<Value> {
        prop_oneof![
            6 => (arbitrary_text(), arbitrary_text(), any::<bool>())
                .prop_map(|(host, line, confirm)| {
                    json!({"host": host, "line": line, "confirm": confirm})
                }),
            1 => arbitrary_json(),
            1 => Just(json!({"host": "lab-1"})),
            1 => Just(json!({"host": [], "line": {}, "confirm": null})),
        ]
        .boxed()
    }

    fn job_arguments() -> BoxedStrategy<Value> {
        prop_oneof![
            6 => arbitrary_text().prop_map(|id| json!({"id": id})),
            1 => arbitrary_json(),
            1 => Just(json!({})),
            1 => Just(json!({"id": [], "unknown": true})),
        ]
        .boxed()
    }

    fn assert_tool_result(result: Result<Value, McpFailure>) -> TestCaseResult {
        match result {
            Ok(value) => prop_assert!(serde_json::to_vec(&value).is_ok()),
            Err(error) => prop_assert!(matches!(
                error,
                McpFailure::InvalidArguments
                    | McpFailure::Forbidden
                    | McpFailure::RouterUnreachable
                    | McpFailure::RouterRejected
                    | McpFailure::ValidationFailed
                    | McpFailure::Conflict
                    | McpFailure::Internal
            )),
        }
        Ok(())
    }

    async fn exercise_tool_arguments(
        server: &KccMcp,
        arguments: &(
            Value,
            Value,
            Value,
            Value,
            Value,
            Value,
            Value,
            Value,
            Value,
        ),
    ) -> TestCaseResult {
        let (list, host, search, describe, read, write, batch, cli, job) = arguments;

        if let Ok(input) = serde_json::from_value::<super::ListInput>(list.clone()) {
            assert_tool_result(server.routers_list_value(input))?;
        }
        if let Ok(input) = serde_json::from_value::<super::HostInput>(host.clone()) {
            assert_tool_result(server.router_info_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::CatalogSearchInput>(search.clone()) {
            assert_tool_result(server.catalog_search_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::CatalogDescribeInput>(describe.clone()) {
            assert_tool_result(server.catalog_describe_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::RciReadInput>(read.clone()) {
            assert_tool_result(server.rci_read_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::RciWriteInput>(write.clone()) {
            assert_tool_result(server.rci_execute_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::RciWriteInput>(write.clone()) {
            assert_tool_result(server.rci_delete_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::RciBatchInput>(batch.clone()) {
            assert_tool_result(server.rci_batch_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::CliInput>(cli.clone()) {
            assert_tool_result(server.cli_parse_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::JobInput>(job.clone()) {
            assert_tool_result(server.job_status_value(input))?;
        }
        if let Ok(input) = serde_json::from_value::<super::JobInput>(job.clone()) {
            assert_tool_result(server.job_cancel_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::HostInput>(host.clone()) {
            assert_tool_result(server.config_state_value(input).await)?;
        }
        if let Ok(input) = serde_json::from_value::<super::HostInput>(host.clone()) {
            assert_tool_result(server.config_save_value(input).await)?;
        }
        Ok(())
    }

    #[test]
    fn random_json_arguments_never_panic() -> Result<(), Box<dyn Error>> {
        let runtime = tokio::runtime::Runtime::new()?;
        let mut config = McpConfig::default();
        config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
        config.allow_destructive = true;
        let fixture = runtime.block_on(Fixture::spawn(config, PrivacyConfig::default()))?;
        let strategy = (
            list_arguments(),
            host_arguments(),
            catalog_search_arguments(),
            catalog_describe_arguments(),
            rci_read_arguments(),
            rci_write_arguments(),
            rci_batch_arguments(),
            cli_arguments(),
            job_arguments(),
        );
        let mut runner = TestRunner::new(ProptestConfig::with_cases(256));
        runner.run(&strategy, |arguments| {
            runtime.block_on(exercise_tool_arguments(&fixture.server, &arguments))
        })?;
        runtime.block_on(fixture.shutdown())?;
        Ok(())
    }
}
