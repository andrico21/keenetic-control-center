//! `kcc mcp settings show`: every Web-managed key with its effective value and source.

#[cfg(test)]
mod tests {
    use kcc_app::mcp_settings::document::McpSettingsDocument;
    use serde_json::Value;

    use crate::{
        fixture::{Fixture, TestResult},
        run::{code, config, kcc, stderr, stdout},
    };

    /// `[mcp]` of the configuration: one kcc.toml value, one locked key.
    const MCP: &str =
        "\n[mcp]\ntoolsets = [\"core\", \"dns\"]\nread_only = true\nlocked = [\"read_only\"]\n";

    /// The `(value, source)` of `key` in the `--json` document.
    fn row(document: &Value, key: &str) -> Option<(Value, String)> {
        document
            .pointer("/settings")?
            .as_array()?
            .iter()
            .find(|row| row.get("key").and_then(Value::as_str) == Some(key))
            .map(|row| {
                (
                    row.get("value").cloned().unwrap_or(Value::Null),
                    row.get("source")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
    }

    /// Regression (todo 32): `settings show` names every key's source and value.
    ///
    /// The JSON document is one value naming each key's source: an environment variable, `[mcp] locked`, the Web (`mcp_settings.json`), kcc.toml and
    /// the default, with the effective value; the human table says the same.
    #[test]
    fn settings_show_names_every_source() -> TestResult {
        let fixture = Fixture::new()?;
        let mut document = McpSettingsDocument::default();
        document.overrides.allow_destructive = Some(true);
        fixture.state()?.write(&document)?;
        let cli = config(&fixture, "admin", MCP)?;
        let env = [("KCC_MCP_MAX_RESULT_BYTES", "4096")];
        let shown = kcc(&fixture, &cli, &["--json", "mcp", "settings", "show"], &env)?;
        assert_eq!(code(&shown), Some(0_i32), "{}", stderr(&shown));
        let json: Value = serde_json::from_str(&stdout(&shown))?;
        for (key, value, source) in [
            ("max_result_bytes", Value::from(4096_u32), "env"),
            ("read_only", Value::Bool(true), "locked"),
            ("allow_destructive", Value::Bool(true), "state"),
            ("toolsets", serde_json::json!(["core", "dns"]), "toml"),
            ("http_enabled", Value::Bool(true), "default"),
            ("auth.oidc.issuer", Value::Null, "default"),
        ] {
            assert_eq!(
                row(&json, key),
                Some((value, source.to_owned())),
                "{key}: {json}"
            );
        }
        assert_eq!(
            json.pointer("/locked"),
            Some(&serde_json::json!(["read_only"]))
        );
        let rows = json
            .pointer("/settings")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        assert_eq!(rows, 27, "every Web-managed key");
        let human = kcc(&fixture, &cli, &["mcp", "settings", "show"], &env)?;
        assert_eq!(code(&human), Some(0_i32), "{}", stderr(&human));
        let text = stdout(&human);
        for line in [
            ("max_result_bytes", "4096", "environment"),
            ("read_only", "true", "kcc.toml (locked)"),
            ("allow_destructive", "true", "Web"),
            ("auth.oidc.issuer", "not set", "default"),
        ] {
            assert!(
                text.lines().any(|candidate| {
                    let words = candidate
                        .split("  ")
                        .map(str::trim)
                        .filter(|word| !word.is_empty())
                        .collect::<Vec<_>>();
                    words == <[&str; 3]>::from(line)
                }),
                "{line:?} in {text}"
            );
        }
        Ok(())
    }
}
