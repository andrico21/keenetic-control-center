//! Client pseudonymization of MCP results.

use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use serde_json::{Value, json};

use super::fixture::Fixture;
use crate::support::{shape::shape, truncate::Shaping};

/// Shapes `value` for a server whose `redact_clients_in_mcp` is `redact`.
async fn shaped(redact: bool, value: Value) -> Result<Value, Box<dyn Error>> {
    let mut privacy = PrivacyConfig::default();
    privacy.redact_clients_in_mcp = redact;
    let fixture = Fixture::spawn(McpConfig::default(), privacy).await?;
    let text = shape(fixture.server(), value, Shaping::new(Some("request")))
        .map_err(|error| format!("shape failed: {error:?}"))?;
    fixture.shutdown().await?;
    Ok(serde_json::from_str(&text)?)
}

/// A clients result with a name, addresses in free text and keys that merely contain "ip".
fn clients_result() -> Value {
    json!({
        "clients": [{
            "mac": "02:00:00:00:00:01",
            "name": "Alice Phone",
            "ip_address": "192.0.2.10",
            "description": "lease for 02:00:00:00:00:01 at 192.0.2.10",
            "script": "plain words",
            "tip": "plain words",
            "recipe": "plain words",
            "interface": "Bridge0"
        }],
        "message": "seen 02:00:00:00:00:02 via 198.51.100.7:443 and 2001:db8::7, then mac=02:00:00:00:00:03."
    })
}

/// E-05: with the setting on, a clients result shows no client name, and MAC, IPv4 and
/// IPv6 patterns inside free-text strings are replaced by the pseudonym the field form gets.
#[tokio::test]
async fn client_names_and_free_text_are_pseudonymized() -> Result<(), Box<dyn Error>> {
    let value = shaped(true, clients_result()).await?;
    let text = value.to_string();
    for leaked in [
        "Alice Phone",
        "02:00:00:00:00:0",
        "192.0.2.10",
        "198.51.100.7",
        "2001:db8",
    ] {
        assert!(!text.contains(leaked), "{leaked} leaked in {text}");
    }
    let client = value.pointer("/clients/0").ok_or("client")?;
    let mac = client.get("mac").and_then(Value::as_str).ok_or("mac")?;
    let description = client
        .get("description")
        .and_then(Value::as_str)
        .ok_or("description")?;
    assert!(
        description.starts_with(&format!("lease for {mac} at ")),
        "{description}"
    );
    assert_eq!(client.get("interface"), Some(&json!("Bridge0")));
    Ok(())
}

/// E-13: `ip` and `ip_address` keys are pseudonymized as whole key tokens; keys that only
/// contain the letters "ip" are not, and a pseudonym is a keyed hash, stable per value.
#[tokio::test]
async fn ip_keys_match_whole_tokens_and_pseudonyms_are_stable() -> Result<(), Box<dyn Error>> {
    let input = json!({
        "ip": "192.0.2.10",
        "ip_address": "192.0.2.10",
        "ipAddress": "192.0.2.11",
        "description": "plain words",
        "script": "plain words",
        "tip": "plain words",
        "recipe": "plain words"
    });
    let value = shaped(true, input.clone()).await?;
    for key in ["description", "script", "tip", "recipe"] {
        assert_eq!(value.get(key), Some(&json!("plain words")), "{key}");
    }
    let ip = value.get("ip").and_then(Value::as_str).ok_or("ip")?;
    assert!(
        ip.strip_prefix("client-").is_some_and(
            |hash| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        ),
        "{ip}"
    );
    assert_eq!(value.get("ip_address"), Some(&json!(ip)));
    assert_ne!(value.get("ipAddress"), Some(&json!(ip)));
    assert_eq!(shaped(true, input).await?.get("ip"), Some(&json!(ip)));
    Ok(())
}

/// With the setting off nothing is pseudonymized.
#[tokio::test]
async fn setting_off_changes_nothing() -> Result<(), Box<dyn Error>> {
    assert_eq!(shaped(false, clients_result()).await?, clients_result());
    Ok(())
}
