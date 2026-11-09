//! Persistence traversal regressions independent of validation rejection.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::{Value, json};

use crate::{Catalog, HttpMethod, ValidatedRequest};

/// Valid deep prefix commands must not disappear next to a persisting command.
#[test]
fn deep_prefix_mixed_requests_remain_unsaved() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for (path, value, ordinary) in [
        (
            "system",
            json!({"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}),
            "system ndss dump-report disable",
        ),
        (
            "system",
            json!({"country":{"country":"DE"},"configuration":{"fail-safe":{"timer":{"interval":60_i32}}}}),
            "system configuration fail-safe timer",
        ),
        (
            "",
            json!({"system":{"country":{"country":"DE"}},"cloud":{"webui":{"cdn":{"mode":"auto"}}}}),
            "cloud webui cdn",
        ),
        (
            "",
            json!({"system":{"country":{"country":"DE"}},"crypto":{"ike":{"nat-keepalive":{"nat-keepalive":30_i32}}}}),
            "crypto ike nat-keepalive",
        ),
    ] {
        let request = catalog
            .validate(path, HttpMethod::Post, &value)
            .map_err(|_issues| "valid deep body refused")?;
        assert!(!request.persists_immediately, "{ordinary}");
        assert_eq!(request.persisted_paths, ["system country"], "{ordinary}");
        assert_eq!(request.ordinary_paths, [ordinary], "{ordinary}");
    }
    Ok(())
}

/// Malformed or unknown nodes cannot supply proof of persistence.
#[test]
fn unproven_nodes_default_to_ordinary() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for child in [
        json!({"unknown":{}}),
        json!([]),
        json!([{}]),
        json!([[{}]]),
        Value::Null,
        json!(true),
        json!(1_i32),
        json!("DE"),
    ] {
        let value = json!({"system":{"country":{"country":"DE"}},"unknown":child});
        let request = ValidatedRequest::capture(&catalog, "", HttpMethod::Post, value, false);
        assert!(
            !request.persists_immediately,
            "unknown leaf must prevent a saved claim"
        );
        assert_eq!(request.ordinary_paths, ["unknown"]);
    }
    for value in [
        json!({"unknown":{}}),
        json!([]),
        json!([{}]),
        json!([[{}]]),
        Value::Null,
        json!(true),
        json!(1_i32),
        json!("DE"),
    ] {
        let request =
            ValidatedRequest::capture(&catalog, "system country", HttpMethod::Post, value, false);
        assert!(
            !request.persists_immediately,
            "malformed persisting command"
        );
        assert!(
            !request.ordinary_paths.is_empty(),
            "unproven leaf must be retained"
        );
    }
    let raw = ValidatedRequest::capture(
        &catalog,
        "system country",
        HttpMethod::Post,
        json!({"country":"DE"}),
        true,
    );
    assert!(!raw.persists_immediately);
    assert_eq!(raw.ordinary_paths, ["system country"]);
    Ok(())
}

/// Arguments and keyword/no forms belong to their command, even beside children.
#[test]
fn own_arguments_keywords_and_no_are_command_leaves() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for (path, body, expected) in [
        (
            "interface",
            json!({"name":"Bridge0","description":{"description":"lab"}}),
            vec!["interface description", "interface"],
        ),
        (
            "ip hotspot host",
            json!({"mac":"02:00:00:00:00:01","permit":true}),
            vec!["ip hotspot host"],
        ),
        (
            "system description",
            json!({"no":true}),
            vec!["system description"],
        ),
        ("system", json!({}), vec!["system"]),
    ] {
        let request = catalog
            .validate(path, HttpMethod::Post, &body)
            .map_err(|issues| format!("{path}: {issues:?}"))?;
        assert!(!request.persists_immediately, "{path}");
        assert_eq!(request.ordinary_paths, expected, "{path}");
    }
    for method in [HttpMethod::Post, HttpMethod::Delete] {
        let request = catalog
            .validate("system country", method, &json!({}))
            .map_err(|_issues| "empty country refused")?;
        assert!(request.persists_immediately);
        assert_eq!(request.persisted_paths, ["system country"]);
    }
    Ok(())
}
