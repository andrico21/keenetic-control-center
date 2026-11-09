//! The `persists_immediately` flag read from the committed catalog data.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "a test fails by panicking or with a boxed error"
)]

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, RawAuthorization};

/// Every committed firmware line.
const LINES: [&str; 3] = ["4.3.0", "5.0.0", "5.1.0"];

#[test]
fn system_country_persists_immediately_on_every_line() -> Result<(), Box<dyn Error>> {
    for line in LINES {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str(line)?, Some("KN-1811"))?;
        let command = catalog
            .lookup("system country")
            .ok_or("system country absent")?;
        assert!(command.persists_immediately, "{line}: system country");
        let description = catalog
            .lookup("interface description")
            .ok_or("interface description absent")?;
        assert!(
            !description.persists_immediately,
            "{line}: ordinary command"
        );
    }
    Ok(())
}

#[test]
fn validated_requests_carry_the_flag_on_every_entry_point() -> Result<(), Box<dyn Error>> {
    let catalog =
        Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
    let path = catalog.validate(
        "system country",
        HttpMethod::Post,
        &json!({"country": "DE"}),
    );
    assert!(path.map_err(|_issues| "path refused")?.persists_immediately);
    let root = catalog.validate(
        "",
        HttpMethod::Post,
        &json!({"system": {"country": {"country": "DE"}}}),
    );
    assert!(root.map_err(|_issues| "root refused")?.persists_immediately);
    let line = catalog.validate_cli("system country DE", RawAuthorization::default());
    assert!(line.map_err(|_issues| "line refused")?.persists_immediately);
    let read = catalog.validate("system country", HttpMethod::Get, &json!({}));
    assert!(!read.map_err(|_issues| "read refused")?.persists_immediately);
    let ordinary = catalog.validate(
        "interface description",
        HttpMethod::Post,
        &json!({"description": "lan"}),
    );
    assert!(
        !ordinary
            .map_err(|_issues| "ordinary refused")?
            .persists_immediately
    );
    Ok(())
}

#[test]
fn validated_requests_classify_persistence_per_leaf_command() -> Result<(), Box<dyn Error>> {
    let catalog =
        Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
    let cases = [
        (
            "single persisting path",
            "system country",
            HttpMethod::Post,
            json!({"country": "DE"}),
            true,
            &["system country"][..],
            &[][..],
        ),
        (
            "nested all persisting",
            "system",
            HttpMethod::Post,
            json!({"country": {"country": "DE"}}),
            true,
            &["system country"][..],
            &[][..],
        ),
        (
            "nested mixed",
            "system",
            HttpMethod::Post,
            json!({
                "country": {"country": "DE"},
                "description": {"description": "lab"}
            }),
            false,
            &["system country"][..],
            &["system description"][..],
        ),
        (
            "ordinary",
            "system description",
            HttpMethod::Post,
            json!({"description": "lab"}),
            false,
            &[][..],
            &["system description"][..],
        ),
        (
            "empty root",
            "",
            HttpMethod::Post,
            json!({}),
            false,
            &[][..],
            &[][..],
        ),
        (
            "read",
            "system country",
            HttpMethod::Get,
            json!({}),
            false,
            &[][..],
            &[][..],
        ),
    ];

    for (name, path, method, value, persists, persisted_paths, ordinary_paths) in cases {
        let request = catalog
            .validate(path, method, &value)
            .map_err(|_issues| "request refused")?;
        assert_eq!(request.persists_immediately, persists, "{name}");
        assert_eq!(request.persisted_paths, persisted_paths, "{name}");
        assert_eq!(request.ordinary_paths, ordinary_paths, "{name}");
    }
    Ok(())
}
