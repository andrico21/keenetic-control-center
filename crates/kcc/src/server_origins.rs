//! Shared HTTP Origin policy assembly.

extern crate alloc;

use alloc::collections::BTreeSet;

use kcc_app::settings::{Config, ConfigError};
use rmcp_server_kit::transport::McpServerConfig;

/// Adds Web UI origins to the operator's shared-listener allowlist.
///
/// # Errors
///
/// Returns [`ConfigError`] when the Web UI transport cannot derive safe origins.
pub(super) fn apply(
    server: McpServerConfig,
    config: &Config,
) -> Result<McpServerConfig, ConfigError> {
    if !config.web.enabled {
        return Ok(server);
    }
    let mut origins = config
        .server
        .allowed_origins
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    origins.extend(config.web_allowed_origins()?);
    Ok(server.with_allowed_origins(origins))
}
