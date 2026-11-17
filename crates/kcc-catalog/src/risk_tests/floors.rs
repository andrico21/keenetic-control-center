//! Risk floors the catalog itself owns, so no front end has to re-derive them.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, RawAuthorization, Risk};

/// A-08: a DELETE validated by the catalog alone is `Destructive`, like its `no` spelling;
/// front ends no longer raise it themselves.
#[test]
fn a_catalog_delete_is_destructive() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        let deleted = catalog
            .validate(
                "ip hotspot host",
                HttpMethod::Delete,
                &json!({"mac":"02:00:00:00:00:41"}),
            )
            .map_err(|issues| format!("{version}: {issues:?}"))?;
        assert_eq!(deleted.risk, Risk::Destructive, "{version}");
        for command in catalog.commands().filter(|command| command.prefix_no) {
            if let Ok(removal) = catalog.validate(&command.path, HttpMethod::Delete, &json!({})) {
                assert_eq!(
                    removal.risk,
                    Risk::Destructive,
                    "{version} {}",
                    command.path
                );
            }
        }
    }
    Ok(())
}

/// E-22: a CLI line the catalog cannot map, sent through the raw escape, is `Destructive`
/// and still runs under the recovery timer.
#[test]
fn an_unvalidated_cli_line_is_destructive() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let authorization = RawAuthorization {
        raw_rci: true,
        admin_manage_routers: true,
    };
    let request = catalog
        .validate_cli("future-command lab", authorization)
        .map_err(|issues| format!("{issues:?}"))?;
    assert!(request.unvalidated);
    assert_eq!(request.risk, Risk::Destructive);
    assert!(request.contains_management());
    Ok(())
}
