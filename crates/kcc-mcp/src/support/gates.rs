//! The live MCP settings every handler reads when a tool call starts: toolsets,
//! read-only mode, the destructive switch and the result cap.
//!
//! Every handler cloned from one [`KccMcp::new`](crate::KccMcp::new) shares one cell. A
//! call is gated by the stricter of that cell and the handler's own settings, so a
//! tightening published to the cell binds open sessions at their next call, while a
//! loosening binds only sessions opened on a handler built with it. The gates are read
//! once per call, so a call never mixes two generations.

use alloc::sync::Arc;

use arc_swap::ArcSwap;
use kcc_app::settings::McpConfig;

use crate::registry::definitions::ToolDescription;

/// The settings a tool call is gated by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpGates {
    /// Toolsets whose tools may run.
    toolsets: Vec<String>,
    /// Only tools that never change router state may run.
    read_only: bool,
    /// Destructive operations may run (with confirmation).
    allow_destructive: bool,
    /// Byte budget of one result.
    max_result_bytes: u32,
}

/// The gates shared by every handler of one server.
pub(crate) type SharedGates = Arc<ArcSwap<McpGates>>;

tokio::task_local! {
    /// The gates of the tool call this task runs.
    static CALL: Arc<McpGates>;
}

impl McpGates {
    /// The gates `config` sets.
    pub(crate) fn new(config: &McpConfig) -> Self {
        Self {
            toolsets: config.toolsets.clone(),
            read_only: config.read_only,
            allow_destructive: config.allow_destructive,
            max_result_bytes: config.max_result_bytes,
        }
    }

    /// The stricter of `self` and `config` on every gate.
    pub(crate) fn narrowed(&self, config: &McpConfig) -> Self {
        Self {
            toolsets: self
                .toolsets
                .iter()
                .filter(|toolset| config.toolsets.contains(toolset))
                .cloned()
                .collect(),
            read_only: self.read_only || config.read_only,
            allow_destructive: self.allow_destructive && config.allow_destructive,
            max_result_bytes: self.max_result_bytes.min(config.max_result_bytes),
        }
    }

    /// Whether `definition` may run: its toolset is on, and it only reads when read-only
    /// mode is on.
    pub(crate) fn admits(&self, definition: &ToolDescription) -> bool {
        self.toolsets
            .iter()
            .any(|toolset| toolset == definition.toolset)
            && (!self.read_only || definition.read_only)
    }

    /// Whether destructive operations may run.
    pub(crate) const fn allow_destructive(&self) -> bool {
        self.allow_destructive
    }

    /// Byte budget of one result.
    pub(crate) const fn max_result_bytes(&self) -> u32 {
        self.max_result_bytes
    }
}

/// Runs `work` as one tool call gated by `gates`.
// cancel-safe: it only scopes `work`, whose own cancel safety applies.
pub(crate) async fn scoped<F>(gates: Arc<McpGates>, work: F) -> F::Output
where
    F: Future,
{
    CALL.scope(gates, work).await
}

/// The gates of the tool call this task runs, if it runs one.
pub(crate) fn of_call() -> Option<Arc<McpGates>> {
    CALL.try_with(Arc::clone).ok()
}
