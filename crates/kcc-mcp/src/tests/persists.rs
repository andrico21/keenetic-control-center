//! Commands the router persists immediately are flagged in the describe output and in
//! every raw-write result; other commands are not.

use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::{Value, json};

use super::fixture::Fixture;
use crate::generic::{
    fleet::{CatalogDescribeInput, catalog_describe},
    rci::{CliInput, RciWriteInput, cli_parse, rci_execute},
};

/// The flag and the notice of one tool result.
fn label(result: &Value) -> (Option<&Value>, Option<&Value>) {
    (result.get("persists_immediately"), result.get("notice"))
}

#[tokio::test]
async fn system_country_is_flagged_before_and_after_it_runs() -> Result<(), Box<dyn Error>> {
    let mut config = McpConfig::default();
    config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
    let fixture = Fixture::spawn(config, PrivacyConfig::default()).await?;
    let notice = Value::String(tr(Locale::En, keys::MCP_PERSISTS_IMMEDIATELY, None));
    let flagged = (Some(&Value::Bool(true)), Some(&notice));
    let plain = (Some(&Value::Bool(false)), None);

    let describe = |path: &str| -> Result<CatalogDescribeInput, serde_json::Error> {
        serde_json::from_value(json!({"host": "lab-1", "path": path}))
    };
    let country = catalog_describe(fixture.server(), describe("system country")?).await;
    assert_eq!(
        label(&country.map_err(|error| format!("{error:?}"))?),
        flagged
    );
    let host = catalog_describe(fixture.server(), describe("ip host")?).await;
    assert_eq!(label(&host.map_err(|error| format!("{error:?}"))?), plain);

    let execute: RciWriteInput = serde_json::from_value(json!({
        "host": "lab-1",
        "catalog_path": "system country",
        "path": ["system", "country"],
        "value": {"country": "DE"}
    }))?;
    let executed = rci_execute(fixture.server(), execute).await;
    assert_eq!(
        label(&executed.map_err(|error| format!("{error:?}"))?),
        flagged
    );
    let ordinary: RciWriteInput = serde_json::from_value(json!({
        "host": "lab-1",
        "catalog_path": "ip host",
        "path": ["ip", "host"],
        "value": {"domain": "mcp.example", "address": "192.0.2.11"}
    }))?;
    let applied = rci_execute(fixture.server(), ordinary).await;
    assert_eq!(
        label(&applied.map_err(|error| format!("{error:?}"))?),
        plain
    );

    let line: CliInput =
        serde_json::from_value(json!({"host": "lab-1", "line": "system country DE"}))?;
    let parsed = cli_parse(fixture.server(), line).await;
    assert_eq!(
        label(&parsed.map_err(|error| format!("{error:?}"))?),
        flagged
    );
    fixture.shutdown().await?;
    Ok(())
}
