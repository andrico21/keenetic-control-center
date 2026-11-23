//! Construction and the macro-generated RMCP router of the generic tools.

use alloc::sync::Arc;
use core::time::Duration;

use arc_swap::ArcSwap;
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
use kcc_domain::entware::ssh::SshServices;
use kcc_migrate::presets::store::PresetStore;
use rmcp::{
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::CallToolResult,
    tool, tool_router,
};
use rmcp_server_kit::rbac::RbacConfig;

use super::{
    fleet::{self, CatalogDescribeInput, CatalogSearchInput, HostInput, JobInput, ListInput},
    rci::{self, CliInput, RciBatchInput, RciReadInput, RciWriteInput},
};
use crate::{
    KccMcp, config_tools, domains, migration_tools, preset_tools,
    preset_tools::state::Presets,
    principals::McpPrincipals,
    registry::definitions::{ToolDescription, enabled, generic, tools},
    support::{
        call::{finish, finish_with_context},
        gates::McpGates,
        shape::FailureContext,
    },
};

#[tool_router]
impl KccMcp {
    /// Builds a handler with toolsets and safety mode applied to both list and dispatch.
    #[inline]
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor wires the application services once and its signature is the public API the binary and the Web UI call"
    )]
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
        let definitions: Arc<[ToolDescription]> = tools().into();
        let (tool_router, tool_specs) = Self::routes(&definitions, &config);
        let gates = Arc::new(ArcSwap::from_pointee(McpGates::new(&config)));
        Self {
            config,
            gates,
            definitions,
            privacy,
            registry,
            workflow,
            jobs,
            poller,
            roles: RoleSource::new(roles),
            fallback_role,
            key_use: None,
            principals: None,
            tool_router,
            tool_specs,
            audit: None,
            migrations: Arc::default(),
            presets: Arc::default(),
            entware_ssh: None,
        }
    }

    /// This handler on the `[mcp]` settings `settings`: only the tool registry is built
    /// again (toolsets and safety mode); every shared service, the migration plans, the
    /// preset state and the live gates are the same ones.
    ///
    /// Open sessions keep the handler they started with; [`KccMcp::publish_gates`] on the
    /// result makes a tightening bind them at their next call.
    #[inline]
    #[must_use]
    pub fn reconfigured(&self, settings: McpConfig) -> Self {
        let (tool_router, tool_specs) = Self::routes(&self.definitions, &settings);
        let mut next = self.clone();
        next.config = settings;
        next.tool_router = tool_router;
        next.tool_specs = tool_specs;
        next
    }

    /// The tool router and the RBAC tool registry of the tools `config` enables.
    fn routes(
        definitions: &[ToolDescription],
        config: &McpConfig,
    ) -> (ToolRouter<Self>, Arc<[ToolSpec]>) {
        let mut tool_router = Self::tool_router();
        for route in domains::routes::routes()
            .into_iter()
            .chain(config_tools::routes::routes())
            .chain(migration_tools::routes::routes())
            .chain(preset_tools::routes::routes())
        {
            tool_router.add_route(route);
        }
        for definition in generic() {
            if let Some(route) = tool_router.map.get_mut(definition.name) {
                route.attr.description = Some(definition.description.into());
                route.attr.annotations = Some(definition.tool_annotations());
            }
        }
        for definition in definitions {
            if !enabled(definition, config) {
                tool_router.remove_route(definition.name);
            }
        }
        let tool_specs = definitions
            .iter()
            .filter(|definition| enabled(definition, config))
            .map(|definition| {
                ToolSpec::new(
                    definition.name.to_owned(),
                    definition.permission,
                    Some(definition.annotations()),
                )
            })
            .collect();
        (tool_router, tool_specs)
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

    /// Resolves the account behind every kcc account token through `principals`, on every
    /// call; without it such tokens are refused.
    #[inline]
    #[must_use]
    pub fn with_principals(mut self, principals: Arc<dyn McpPrincipals>) -> Self {
        self.principals = Some(principals);
        self
    }

    /// Attaches the encrypted preset store used by the `presets` toolset.
    #[inline]
    #[must_use]
    pub fn with_presets(mut self, store: PresetStore) -> Self {
        self.presets = Arc::new(Presets::new(store));
        self
    }

    /// Attaches the Entware SSH services the `entware-ssh` toolset runs on, shared with the
    /// other surfaces (one session per router); a read that has not finished within
    /// `read_limit` (for example behind a long mutation holding the router's session) is
    /// answered `conflict`.
    #[inline]
    #[must_use]
    pub fn with_entware_ssh(mut self, services: Arc<SshServices>, read_limit: Duration) -> Self {
        self.entware_ssh = Some((services, read_limit));
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

    #[tool(name = "kcc_routers_list")]
    // NOT cancel-safe: it runs through `finish_with_context`, which audits a failure; the queued
    // audit entry may be written after the future is dropped.
    async fn routers_list(&self, Parameters(input): Parameters<ListInput>) -> CallToolResult {
        let (fields, cursor) = input.shape_input();
        finish_with_context(
            self,
            FailureContext::new("kcc_routers_list", true, None).with_input(&fields, cursor),
            async { fleet::routers_list(self, &input) },
        )
        .await
    }

    #[tool(name = "kcc_router_info")]
    // NOT cancel-safe: it runs through `finish`, which audits a failure; the queued audit entry may
    // be written after the future is dropped.
    async fn router_info(&self, Parameters(input): Parameters<HostInput>) -> CallToolResult {
        finish(
            self,
            "kcc_router_info",
            true,
            fleet::router_info(self, input),
        )
        .await
    }

    #[tool(name = "kcc_catalog_search")]
    // NOT cancel-safe: it runs through `finish_with_context`, which audits a failure; the queued
    // audit entry may be written after the future is dropped.
    async fn catalog_search(
        &self,
        Parameters(input): Parameters<CatalogSearchInput>,
    ) -> CallToolResult {
        let (fields, cursor) = input.shape_input();
        finish_with_context(
            self,
            FailureContext::new("kcc_catalog_search", true, None).with_input(&fields, cursor),
            fleet::catalog_search(self, input),
        )
        .await
    }

    #[tool(name = "kcc_catalog_describe")]
    // NOT cancel-safe: it runs through `finish`, which audits a failure; the queued audit entry may
    // be written after the future is dropped.
    async fn catalog_describe(
        &self,
        Parameters(input): Parameters<CatalogDescribeInput>,
    ) -> CallToolResult {
        finish(
            self,
            "kcc_catalog_describe",
            true,
            fleet::catalog_describe(self, input),
        )
        .await
    }

    #[tool(name = "kcc_rci_read")]
    // NOT cancel-safe: it runs through `finish_with_context`, which audits a failure; the queued
    // audit entry may be written after the future is dropped.
    async fn rci_read(&self, Parameters(input): Parameters<RciReadInput>) -> CallToolResult {
        let router = input.router().to_owned();
        let fields = input.fields().to_vec();
        finish_with_context(
            self,
            FailureContext::new("kcc_rci_read", true, Some(&router)).with_input(&fields, None),
            rci::rci_read(self, input),
        )
        .await
    }

    #[tool(name = "kcc_rci_execute")]
    // NOT cancel-safe: the RCI write may reach the router, and the call's audit entries be queued,
    // before the future is dropped.
    async fn rci_execute(&self, Parameters(input): Parameters<RciWriteInput>) -> CallToolResult {
        let router = input.router().to_owned();
        finish_with_context(
            self,
            FailureContext::new("kcc_rci_execute", false, Some(&router)),
            Box::pin(rci::rci_execute(self, input)),
        )
        .await
    }

    #[tool(name = "kcc_rci_delete")]
    // NOT cancel-safe: the RCI delete may reach the router, and the call's audit entries be queued,
    // before the future is dropped.
    async fn rci_delete(&self, Parameters(input): Parameters<RciWriteInput>) -> CallToolResult {
        let router = input.router().to_owned();
        finish_with_context(
            self,
            FailureContext::new("kcc_rci_delete", false, Some(&router)),
            Box::pin(rci::rci_delete(self, input)),
        )
        .await
    }

    #[tool(name = "kcc_rci_batch")]
    // NOT cancel-safe: the RCI batch may reach the router, and the call's audit entries be queued,
    // before the future is dropped.
    async fn rci_batch(&self, Parameters(input): Parameters<RciBatchInput>) -> CallToolResult {
        let router = input.router().to_owned();
        finish_with_context(
            self,
            FailureContext::new("kcc_rci_batch", false, Some(&router)),
            Box::pin(rci::rci_batch(self, input)),
        )
        .await
    }

    #[tool(name = "kcc_cli_parse")]
    // NOT cancel-safe: the parsed CLI command may reach the router, and the call's audit entries be
    // queued, before the future is dropped.
    async fn cli_parse(&self, Parameters(input): Parameters<CliInput>) -> CallToolResult {
        let router = input.router().to_owned();
        finish_with_context(
            self,
            FailureContext::new("kcc_cli_parse", false, Some(&router)),
            Box::pin(rci::cli_parse(self, input)),
        )
        .await
    }

    #[tool(name = "kcc_job_status")]
    // NOT cancel-safe: it runs through `finish`, which audits a failure; the queued audit entry may
    // be written after the future is dropped.
    async fn job_status(&self, Parameters(input): Parameters<JobInput>) -> CallToolResult {
        finish(self, "kcc_job_status", true, async {
            fleet::job_status(self, &input)
        })
        .await
    }

    #[tool(name = "kcc_job_cancel")]
    // NOT cancel-safe: the job may be cancelled, and the call's audit entries queued, before the
    // future is dropped.
    async fn job_cancel(&self, Parameters(input): Parameters<JobInput>) -> CallToolResult {
        finish(
            self,
            "kcc_job_cancel",
            false,
            fleet::job_cancel(self, input),
        )
        .await
    }
}
