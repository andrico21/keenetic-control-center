//! Tool descriptions shared by registration, RBAC, and the generated reference.

use kcc_app::{permissions::Permission, settings::McpConfig};
use serde_json::{Value, json};

use crate::{config_tools, domains, migration_tools, preset_tools};

/// One registered tool as clients and the coarse RBAC gate see it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ToolDescription {
    /// Protocol tool name, `kcc_<area>_<verb>`.
    pub name: &'static str,
    /// One-line English description.
    pub description: &'static str,
    /// Toolset that registers the tool (`[mcp] toolsets`).
    pub toolset: &'static str,
    /// Coarse permission checked by kit RBAC; handlers re-check the exact operation.
    pub permission: Permission,
    /// Whether the tool never changes router state.
    pub read_only: bool,
    /// Whether any operation of the tool is destructive.
    pub destructive: bool,
    /// Whether repeating a call has no further effect.
    pub idempotent: bool,
    /// Operation names accepted by the `op` argument; empty for single-purpose tools.
    pub ops: Vec<&'static str>,
}

impl ToolDescription {
    /// Describes a single-purpose tool.
    #[must_use]
    pub(crate) const fn single(
        name: &'static str,
        description: &'static str,
        toolset: &'static str,
        permission: Permission,
        hints: (bool, bool, bool),
    ) -> Self {
        let (read_only, destructive, idempotent) = hints;
        Self {
            name,
            description,
            toolset,
            permission,
            read_only,
            destructive,
            idempotent,
            ops: Vec::new(),
        }
    }

    /// Returns a copy that accepts `ops` as its `op` argument.
    #[must_use]
    pub(crate) fn with_ops(mut self, ops: Vec<&'static str>) -> Self {
        self.ops = ops;
        self
    }

    /// MCP annotation object fed to application RBAC.
    #[inline]
    #[must_use]
    pub fn annotations(&self) -> Value {
        json!({
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": false
        })
    }
}

/// Read-only hints: read only, not destructive, idempotent.
const READ: (bool, bool, bool) = (true, false, true);

/// The generic tools of the MCP core.
fn generic() -> Vec<ToolDescription> {
    let raw = |name, description, idempotent| {
        ToolDescription::single(
            name,
            description,
            "raw",
            Permission::RawRci,
            (false, true, idempotent),
        )
    };
    vec![
        ToolDescription::single(
            "kcc_routers_list",
            "List authorized router profiles",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_router_info",
            "Read router identity, firmware, capabilities, and support tier",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_catalog_search",
            "Search commands available on a router",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_catalog_describe",
            "Return the JSON Schema for one router command",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_rci_read",
            "Run a catalog-validated read-only RCI request",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_job_status",
            "Read a background job status",
            "core",
            Permission::Read,
            READ,
        ),
        ToolDescription::single(
            "kcc_job_cancel",
            "Cancel a running background job",
            "core",
            Permission::Write,
            (false, false, true),
        ),
        raw(
            "kcc_rci_execute",
            "Apply a catalog-validated raw RCI mutation without saving",
            false,
        ),
        raw(
            "kcc_rci_delete",
            "Apply a catalog-validated RCI deletion without saving",
            true,
        ),
        raw(
            "kcc_rci_batch",
            "Apply catalog-validated root RCI mutations without saving",
            false,
        ),
        raw(
            "kcc_cli_parse",
            "Validate and apply one router CLI line without saving",
            false,
        ),
    ]
}

/// Every tool the server can register, in documentation order.
#[inline]
#[must_use]
pub fn tools() -> Vec<ToolDescription> {
    let mut all = generic();
    all.extend(config_tools::routes::descriptions());
    all.extend(domains::table::descriptions());
    all.extend(migration_tools::routes::descriptions());
    all.extend(preset_tools::routes::descriptions());
    all
}

/// Whether `[mcp]` registers `definition`.
pub(crate) fn enabled(definition: &ToolDescription, config: &McpConfig) -> bool {
    config
        .toolsets
        .iter()
        .any(|toolset| toolset == definition.toolset)
        && (!config.read_only || definition.read_only)
}
