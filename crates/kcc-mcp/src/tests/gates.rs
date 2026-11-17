//! Registration, authorization, redaction, and result-budget gates.

use core::error::Error;

use kcc_app::{
    permissions::Permission,
    settings::{McpConfig, PrivacyConfig},
};
use rmcp::ServerHandler as _;
use serde_json::{Value, json};

use super::fixture::{Fixture, lab_role, operator_role, viewer_role};
use crate::{
    McpFailure, McpIdentity, RouterId, authorize_routers,
    generic::rci::{RciWriteInput, rci_execute},
    registry::definitions::tools,
    support::{
        shape::{pseudonymize, shape},
        truncate::Shaping,
    },
};

#[tokio::test]
async fn fallback_role_filters_stdio_tools_without_changing_http_inventory()
-> Result<(), Box<dyn Error>> {
    let viewer = Fixture::spawn_with_role(
        McpConfig::default(),
        PrivacyConfig::default(),
        viewer_role(),
    )
    .await?;
    let viewer_tools = viewer.server().visible_tools(false);
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
        viewer.server().visible_tools(true),
        viewer.server().tool_router.list_all(),
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
            .server()
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
    let core_count = tools()
        .iter()
        .filter(|definition| definition.toolset == "core")
        .count();
    assert!(core_count <= 25);
    assert!(tools().len() <= 70);
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
    let tools = fixture.server().get_info();
    assert!(tools.capabilities.tools.is_some());
    assert!(fixture.server().tool_specs().len() <= 25);
    fixture.shutdown().await?;

    let mut config = McpConfig::default();
    config.read_only = true;
    config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
    let read_only = Fixture::spawn(config, PrivacyConfig::default()).await?;
    assert!(read_only.server().tool_specs().iter().all(|spec| {
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
    let before = fixture.requests();
    let input: RciWriteInput = serde_json::from_value(json!({
        "host": "lab-1",
        "catalog_path": "system reboot",
        "path": ["system", "reboot"],
        "value": {"unexpected": "incident"},
        "confirm": true
    }))?;
    let invalid = rci_execute(fixture.server(), input).await;
    assert_eq!(invalid, Err(McpFailure::ValidationFailed));
    assert_eq!(fixture.requests(), before);

    assert_eq!(
        fixture
            .server()
            .require_destructive(kcc_catalog::Risk::Destructive, true),
        Err(McpFailure::DestructiveDisabled)
    );
    fixture.shutdown().await?;
    let mut enabled = McpConfig::default();
    enabled.allow_destructive = true;
    let switched_on = Fixture::spawn(enabled, PrivacyConfig::default()).await?;
    assert_eq!(
        switched_on
            .server()
            .require_destructive(kcc_catalog::Risk::Destructive, false),
        Err(McpFailure::ConfirmRequired)
    );
    assert_eq!(
        switched_on
            .server()
            .require_destructive(kcc_catalog::Risk::Destructive, true),
        Ok(())
    );
    switched_on.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_result_returns_truncation_marker() -> Result<(), Box<dyn Error>> {
    let mut config = McpConfig::default();
    config.max_result_bytes = 96;
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let text = shape(
        fixture.server(),
        json!({"value":"x".repeat(1024)}),
        Shaping::new(Some("request")),
    )
    .map_err(|error| format!("shape failed: {error:?}"))?;
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(value.get("truncated"), Some(&Value::Bool(true)));
    assert_eq!(value.get("next_cursor"), None);
    fixture.shutdown().await?;
    Ok(())
}

#[test]
fn tool_reference_lists_every_registered_tool_once() {
    let text = crate::registry::docs::markdown();
    for tool in tools() {
        assert_eq!(
            text.matches(&format!("| `{}` |", tool.name)).count(),
            1,
            "{} must have exactly one reference row",
            tool.name
        );
    }
}
