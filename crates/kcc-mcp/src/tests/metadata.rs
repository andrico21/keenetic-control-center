//! One source of tool metadata: the listed generic tools are the `generic()` definitions.

use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use serde_json::to_value;

use super::fixture::Fixture;
use crate::registry::definitions::{generic, tools, toolset};

/// E-14: every generic tool is listed with the description and annotations of its
/// `generic()` definition, so editing one place cannot make a listed tool drift.
#[tokio::test]
async fn generic_tools_are_listed_as_defined() -> Result<(), Box<dyn Error>> {
    let mut toolsets: Vec<String> = tools()
        .iter()
        .map(|definition| definition.toolset.to_owned())
        .collect();
    toolsets.sort();
    toolsets.dedup();
    let mut config = McpConfig::default();
    config.toolsets = toolsets;
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let listed = fixture.server().tool_router.list_all();
    for definition in generic() {
        let tool = listed
            .iter()
            .find(|tool| tool.name == definition.name)
            .ok_or_else(|| format!("{} is not listed", definition.name))?;
        assert_eq!(
            tool.description.as_deref(),
            Some(definition.description),
            "description of {}",
            definition.name
        );
        assert_eq!(
            to_value(&tool.annotations)?,
            definition.annotations(),
            "annotations of {}",
            definition.name
        );
    }
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 23: every tool belongs to a toolset the lookup knows, and only `raw` and (todo 17)
/// `entware-ssh` reduce safety when turned on.
#[test]
fn every_tool_names_a_known_toolset_and_raw_reduces_safety() -> Result<(), Box<dyn Error>> {
    for definition in tools() {
        let info = toolset(definition.toolset)
            .ok_or_else(|| format!("{} names an unknown toolset", definition.name))?;
        assert_eq!(
            info.safety_reducing,
            matches!(info.name, "raw" | "entware-ssh"),
            "safety metadata of {}",
            info.name
        );
    }
    assert_eq!(toolset("shell"), None, "unknown toolset");
    Ok(())
}
