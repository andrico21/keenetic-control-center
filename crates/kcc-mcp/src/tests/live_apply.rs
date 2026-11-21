//! A reconfigured handler rebuilds only its tool registry.

use alloc::sync::Arc;
use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use serde_json::Value;

use super::fixture::Fixture;

/// Todo 25: `reconfigured` shares the very same migration plans, preset state, services
/// and live gates as the handler it came from; only the tool registry is new.
#[tokio::test]
async fn reconfigured_keeps_every_shared_arc() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::spawn(McpConfig::default(), PrivacyConfig::default()).await?;
    let server = fixture.server();
    let mut settings = McpConfig::default();
    settings.read_only = true;

    let next = server.reconfigured(settings.clone());

    assert!(
        Arc::ptr_eq(&server.migrations, &next.migrations),
        "migrations"
    );
    assert!(Arc::ptr_eq(&server.presets, &next.presets), "presets");
    assert!(Arc::ptr_eq(&server.registry, &next.registry), "registry");
    assert!(Arc::ptr_eq(&server.workflow, &next.workflow), "workflow");
    assert!(Arc::ptr_eq(&server.jobs, &next.jobs), "jobs");
    assert!(Arc::ptr_eq(&server.poller, &next.poller), "poller");
    assert!(Arc::ptr_eq(&server.gates, &next.gates), "gates");
    assert!(
        Arc::ptr_eq(&server.definitions, &next.definitions),
        "definitions"
    );
    assert_eq!(next.config, settings, "the new settings");
    assert!(
        next.tool_specs.len() < server.tool_specs.len()
            && next.tool_specs.iter().all(|spec| spec
                .annotations
                .as_ref()
                .and_then(|hints| hints.get("readOnlyHint"))
                == Some(&Value::Bool(true))),
        "only the read tools are registered"
    );
    fixture.shutdown().await
}
