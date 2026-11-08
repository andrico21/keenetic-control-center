//! Construction and the macro-generated RMCP router of the generic tools.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::Mutex;

use kcc_app::{
    api_key_use::KeyUseRecorder,
    audit::AuditLog,
    jobs::JobRunner,
    permissions::{Role, ToolSpec, rbac_config},
    poller::Poller,
    registry::RouterRegistry,
    role_source::RoleSource,
    settings::{McpConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_migrate::presets::store::PresetStore;
use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use rmcp_server_kit::rbac::RbacConfig;

use super::{
    fleet::{self, CatalogDescribeInput, CatalogSearchInput, HostInput, JobInput, ListInput},
    rci::{self, CliInput, RciBatchInput, RciReadInput, RciWriteInput},
};
use crate::{
    KccMcp, config_tools, domains, migration_tools, preset_tools,
    preset_tools::state::Presets,
    registry::definitions::{enabled, tools},
    support::shape::finish,
};

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
        let definitions = tools();
        let mut tool_router = Self::tool_router();
        for route in domains::routes::routes()
            .into_iter()
            .chain(config_tools::routes::routes())
            .chain(migration_tools::routes::routes())
            .chain(preset_tools::routes::routes())
        {
            tool_router.add_route(route);
        }
        for definition in &definitions {
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
                    Some(definition.annotations()),
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
            roles: RoleSource::new(roles),
            fallback_role,
            key_use: None,
            tool_router,
            tool_specs: tool_specs.into(),
            pseudonyms: Arc::new(Mutex::new(BTreeMap::new())),
            audit: None,
            migrations: Arc::default(),
            presets: Arc::default(),
        }
    }

    /// Attaches the audit writer that migration applies record their acknowledgements in.
    #[inline]
    #[must_use]
    pub fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Authorizes against `roles`, shared with the Web UI and the reloads, instead of the
    /// roles given to [`KccMcp::new`]: a role edited or reduced elsewhere binds the next
    /// call.
    #[inline]
    #[must_use]
    pub fn with_role_source(mut self, roles: RoleSource) -> Self {
        self.roles = roles;
        self
    }

    /// Records the last use of the API key behind each authenticated tool call through
    /// `recorder` (throttled per key).
    #[inline]
    #[must_use]
    pub fn with_key_use(mut self, recorder: Arc<KeyUseRecorder>) -> Self {
        self.key_use = Some(recorder);
        self
    }

    /// Attaches the encrypted preset store used by the `presets` toolset.
    #[inline]
    #[must_use]
    pub fn with_presets(mut self, store: PresetStore) -> Self {
        self.presets = Arc::new(Presets::new(store));
        self
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
        rbac_config(&self.roles.current(), &self.tool_specs)
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
        finish(self, fleet::routers_list(self, input))
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
        finish(self, fleet::router_info(self, input).await)
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
        finish(self, fleet::catalog_search(self, input).await)
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
        finish(self, fleet::catalog_describe(self, input).await)
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
        finish(self, rci::rci_read(self, input).await)
    }

    #[tool(
        name = "kcc_rci_execute",
        description = "Apply a catalog-validated raw RCI mutation without saving; kcc_catalog_describe and the result report persists_immediately for commands the router saves at once, which the fail-safe timer cannot roll back",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn rci_execute(&self, Parameters(input): Parameters<RciWriteInput>) -> CallToolResult {
        finish(self, rci::rci_execute(self, input).await)
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
        finish(self, rci::rci_delete(self, input).await)
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
        finish(self, rci::rci_batch(self, input).await)
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
        finish(self, rci::cli_parse(self, input).await)
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
        finish(self, fleet::job_status(self, input))
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
        finish(self, fleet::job_cancel(self, input).await)
    }
}
