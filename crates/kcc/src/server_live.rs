//! Live MCP settings of a running `kcc serve`: the handler each new MCP session clones,
//! and applying toolsets, read-only mode, the destructive switch and the result cap
//! without a restart.

extern crate alloc;

use alloc::sync::Arc;
use std::sync::{Mutex, PoisonError};

use arc_swap::ArcSwap;
use kcc_app::mcp_settings::Effective;
use kcc_mcp::KccMcp;
use kcc_web::admin::{AuthReload as _, ReloadError, TransportReload};

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests;

/// Applies the live `[mcp]` settings to a running `kcc serve`.
#[derive(Debug)]
pub struct McpApply {
    /// The handler every new MCP session clones.
    handler: Arc<ArcSwap<KccMcp>>,
    /// The key and role reload fan-out of every running MCP server.
    reload: Arc<TransportReload>,
    /// Serializes applies, so two cannot interleave their handler swaps.
    applying: Mutex<()>,
}

impl McpApply {
    /// Applies settings to the sessions cloned from `handler` and to the RBAC policy of
    /// the servers registered with `reload`.
    #[inline]
    #[must_use]
    pub const fn new(handler: Arc<ArcSwap<KccMcp>>, reload: Arc<TransportReload>) -> Self {
        Self {
            handler,
            reload,
            applying: Mutex::new(()),
        }
    }

    /// Applies the live keys of `effective`: open sessions are bound by a tightening at
    /// their next call, new sessions start on a handler reconfigured with them, and every
    /// running server's RBAC policy is rebuilt from that handler's tools. With
    /// `http_enabled` off no tool is registered. It reads `roles.json`: call it off the
    /// async executor.
    ///
    /// # Errors
    ///
    /// [`ReloadError::Failed`] when the roles cannot be read: the gates and the handler
    /// are applied, so a tightening holds, and the servers keep their previous RBAC
    /// policy, which refuses every newly enabled tool, until the next role reload.
    #[inline]
    pub fn apply(&self, effective: &Effective) -> Result<(), ReloadError> {
        let _serialized = self.applying.lock().unwrap_or_else(PoisonError::into_inner);
        let mut settings = effective.settings().clone();
        if !settings.http_enabled {
            settings.toolsets.clear();
        }
        let next = self.handler.load().reconfigured(settings);
        next.publish_gates();
        self.reload.set_tools(next.tool_specs().to_vec());
        self.handler.store(Arc::new(next));
        self.reload.reload_rbac()
    }
}
