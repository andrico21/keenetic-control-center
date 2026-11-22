//! Tool descriptions shared by registration, RBAC, and the generated reference.

use kcc_app::{permissions::Permission, settings::McpConfig};
use rmcp::model::ToolAnnotations;
use serde_json::{Value, json};

use crate::{config_tools, domains, migration_tools, preset_tools};

/// One toolset (`[mcp] toolsets`) and whether turning it on reduces safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ToolsetInfo {
    /// Toolset name.
    pub name: &'static str,
    /// Turning the toolset on is a safety-reducing MCP settings change.
    pub safety_reducing: bool,
}

/// Builds a toolset with its documentation summary.
const fn entry(
    name: &'static str,
    safety_reducing: bool,
    summary: &'static str,
) -> (ToolsetInfo, &'static str) {
    (
        ToolsetInfo {
            name,
            safety_reducing,
        },
        summary,
    )
}

/// Every toolset with its one-line summary for `docs/MCP_TOOLS.md`, in documentation order.
pub(crate) const TOOLSETS: &[(ToolsetInfo, &str)] = &[
    entry(
        "core",
        false,
        "Registered by default: fleet, catalog, jobs, configuration state and the main reads.",
    ),
    entry(
        "network-write",
        false,
        "Network reads and writes: interfaces, WAN, Wi-Fi, mesh, clients, DHCP, segments, routing, policies, NAT, firewall.",
    ),
    entry("vpn", false, "VPN clients and servers."),
    entry("dns", false, "DNS proxy and KeenDNS."),
    entry(
        "system-admin",
        false,
        "System changes, diagnostics, router users, services, components, storage, schedules, logging and backups.",
    ),
    entry(
        "migration",
        false,
        "Configuration migration between routers.",
    ),
    entry(
        "presets",
        false,
        "Settings presets: capture settings groups from a router or backup and apply them to another router.",
    ),
    entry("raw", true, "Catalog-validated raw RCI and CLI access."),
    entry(
        "entware",
        false,
        "Entware over the router API: status, drives, the guided setup job and the opkg settings.",
    ),
];

/// The toolset named `name`, if any.
#[inline]
#[must_use]
pub fn toolset(name: &str) -> Option<ToolsetInfo> {
    TOOLSETS
        .iter()
        .map(|&(info, _summary)| info)
        .find(|info| info.name == name)
}

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

    /// The listed tool's annotations.
    #[must_use]
    pub(crate) fn tool_annotations(&self) -> ToolAnnotations {
        ToolAnnotations::new()
            .read_only(self.read_only)
            .destructive(self.destructive)
            .idempotent(self.idempotent)
            .open_world(false)
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
pub(crate) fn generic() -> Vec<ToolDescription> {
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
            "Apply a catalog-validated raw RCI mutation without saving; kcc_catalog_describe and the result report persists_immediately for commands the router saves at once, which the fail-safe timer cannot roll back",
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
            "Validate and apply one router CLI line without saving; lines the catalog cannot map are sent unvalidated as destructive changes (requires RawRci, ManageRouters and Destructive, allow_destructive and confirm) and always reported unsaved",
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
