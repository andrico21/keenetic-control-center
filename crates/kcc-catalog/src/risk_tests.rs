//! Exhaustive nesting properties over the finite embedded command catalogs.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions report a broken classification contract"
)]

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, Risk, ValidatedRequest};

mod independent;
mod management;
mod namespaces;
mod shows;

/// Every command and every split retains the maximum risk of its command nodes.
#[test]
fn every_catalog_command_retains_risk_at_every_nesting_depth() -> Result<(), Box<dyn Error>> {
    for line in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(line)?, None)?;
        for command in catalog.commands() {
            let words = command.path.split_whitespace().collect::<Vec<_>>();
            let leaf_risk = catalog.risk(&command.path).ok_or("visible command risk")?;
            for split in 0..=words.len() {
                let prefix = words
                    .iter()
                    .take(split)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                let value = words
                    .iter()
                    .skip(split)
                    .rev()
                    .fold(json!({}), |child, word| json!({*word: child}));
                let expected = (split.max(1)..=words.len())
                    .filter_map(|depth| {
                        let node = words
                            .iter()
                            .take(depth)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" ");
                        catalog.risk(&node)
                    })
                    .max()
                    .ok_or("command has words")?;
                // Capture also covers virtual request prefixes and argument/child
                // collisions which the public validator conservatively refuses.
                let request = ValidatedRequest::capture(
                    &catalog,
                    &prefix,
                    HttpMethod::Post,
                    value.clone(),
                    false,
                );
                assert!(
                    request.risk >= leaf_risk,
                    "{line}: {} at {split}",
                    command.path
                );
                assert_eq!(
                    request.risk, expected,
                    "{line}: {} at {split}",
                    command.path
                );
                if let Ok(validated) = catalog.validate(&prefix, HttpMethod::Post, &value) {
                    assert_eq!(
                        validated.risk, expected,
                        "public {line}: {} at {split}",
                        command.path
                    );
                }
            }
        }
    }
    Ok(())
}

/// Public validation raises parent risk for destructive and management descendants.
#[test]
fn nested_requests_enforce_leaf_risk_through_public_validation() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for (path, value, expected) in [
        ("system reboot", json!({}), Risk::Destructive),
        ("system", json!({"reboot":{}}), Risk::Destructive),
        (
            "",
            json!({"system":{"configuration":{"factory-reset":{}}}}),
            Risk::Destructive,
        ),
        (
            "",
            json!({"ip":{"http":{"port":{"port":8082_u16}}}}),
            Risk::Management,
        ),
        (
            "system",
            json!({"description":{"description":"lab"}}),
            Risk::Write,
        ),
        ("", json!({}), Risk::Read),
    ] {
        let request = catalog
            .validate(path, HttpMethod::Post, &value)
            .map_err(|issues| format!("{path}: {issues:?}"))?;
        assert_eq!(request.risk, expected, "{path}");
    }
    Ok(())
}
