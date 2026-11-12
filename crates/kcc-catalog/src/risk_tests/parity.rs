//! Structural parity between generated CLI grammar and name-keyed raw JSON.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, RawAuthorization, Risk};

/// Every generated spelling accepted by both validators has one risk verdict.
#[test]
fn cli_and_structured_spellings_have_identical_risk() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        let mut compared = 0_usize;
        for (line, body) in catalog.raw_parity_cases() {
            let Ok(cli) = catalog.validate_cli(&line, RawAuthorization::default()) else {
                continue;
            };
            let Ok(structured) = catalog.validate("", HttpMethod::Post, &body) else {
                continue;
            };
            assert_eq!(cli.risk, structured.risk, "{version}: {line}: {body}");
            assert_eq!(
                cli.contains_management(),
                structured.contains_management(),
                "{version}: {line}: {body}"
            );
            compared = compared.saturating_add(1);
        }
        assert!(compared != 0, "{version}: no shared generated spellings");
    }
    Ok(())
}

/// Removal semantics, rather than descendant selection, determine management parity.
#[test]
fn interface_removal_siblings_keep_management_parity() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let cli = catalog
        .validate_cli("no interface Bridge0", RawAuthorization::default())
        .map_err(|issues| format!("CLI removal: {issues:?}"))?;
    for (path, method, body) in [
        (
            "",
            HttpMethod::Post,
            json!({"interface":{"name":"Bridge0","no":true,"description":{"description":"lab"}}}),
        ),
        (
            "interface",
            HttpMethod::Post,
            json!({"name":"Bridge0","no":true,"description":{}}),
        ),
        (
            "interface",
            HttpMethod::Delete,
            json!({"name":"Bridge0","ip":{"mtu":{"mtu":1_500_i32}}}),
        ),
    ] {
        let structured = catalog
            .validate(path, method, &body)
            .map_err(|issues| format!("{method:?} {path} {body}: {issues:?}"))?;
        assert_eq!(structured.risk, Risk::Destructive, "{method:?} {body}");
        assert_eq!(
            structured.contains_management(),
            cli.contains_management(),
            "{method:?} {body}"
        );
    }
    Ok(())
}
