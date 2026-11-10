//! Literal safety expectations independent of the runtime classification rules.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::{Value, json};

use crate::{Catalog, HttpMethod, RawAuthorization, Risk, ValidatedRequest};

/// Each entry names an independently required security outcome, not a computed oracle.
const INTENTS: &[(&str, Risk)] = &[
    ("system reboot", Risk::Destructive),
    ("system configuration factory-reset", Risk::Destructive),
    ("system configuration fail-safe rollback", Risk::Destructive),
    ("components commit", Risk::Destructive),
    ("erase", Risk::Destructive),
    ("copy", Risk::Destructive),
    ("interface esim profile delete", Risk::Destructive),
    ("media partition format", Risk::Destructive),
    ("mws member reboot", Risk::Destructive),
    ("mws reboot", Risk::Destructive),
    ("system eject", Risk::Destructive),
    ("ip http port", Risk::Management),
    ("user", Risk::Management),
    ("interface ip address", Risk::Management),
    ("interface up", Risk::Management),
    ("interface down", Risk::Management),
];

/// Enumerates all contiguous word groupings, including multiword JSON keys.
fn spellings(words: &[&str], leaf: &Value) -> Vec<Value> {
    if words.is_empty() {
        return vec![leaf.clone()];
    }
    let mut values = Vec::new();
    for width in 1..=words.len() {
        let (key, remaining) = words.split_at(width);
        for child in spellings(remaining, leaf) {
            values.push(json!({key.join(" "): child}));
        }
    }
    values
}

/// Every admitted spelling of a literal dangerous intent preserves its required risk.
#[test]
fn literal_intents_cover_every_admitted_spelling() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for &(path, expected) in INTENTS {
            if catalog.lookup(path).is_none() {
                continue;
            }
            let direct = catalog.validate(path, HttpMethod::Post, &json!({}));
            assert_eq!(
                direct.map(|request| request.risk),
                Ok(expected),
                "{version} {path}"
            );
            let mixed = json!({"system":{"description":{"description":"lab"}}, path:{}});
            let mixed_request = catalog
                .validate("", HttpMethod::Post, &mixed)
                .map_err(|issues| format!("{version} {path}: {issues:?}"))?;
            assert_eq!(mixed_request.risk, expected);
            let words = path.split_whitespace().collect::<Vec<_>>();
            for split in 0..=words.len() {
                let (prefix, remainder) = words.split_at(split);
                for (leaf, required) in [
                    (json!({}), expected),
                    (json!({"no":true}), Risk::Destructive),
                ] {
                    for body in spellings(remainder, &leaf) {
                        match catalog.validate(&prefix.join(" "), HttpMethod::Post, &body) {
                            Ok(request) => {
                                assert_eq!(
                                    request.risk, required,
                                    "{version} {path} {split} {body}"
                                );
                            }
                            Err(issues) => {
                                assert!(!issues.is_empty(), "refused spellings carry issues");
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Root whole-path leaves retain their own persistence and nested descendants.
#[test]
fn whole_path_keys_preserve_persistence() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for body in [
        json!({"system country":{"country":"DE"}}),
        json!({"system":{"country":{"country":"DE"}}}),
    ] {
        let request = catalog
            .validate("", HttpMethod::Post, &body)
            .map_err(|issues| format!("{issues:?}"))?;
        assert_eq!(request.persisted_paths, ["system country"]);
        assert!(request.persists_immediately);
        assert!(request.ordinary_paths.is_empty(), "no ordinary leaves");
    }
    Ok(())
}

/// Every negative spelling shares the destructive DELETE floor, including CLI lines.
#[test]
fn removals_have_the_delete_risk_floor() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for command in catalog.commands().filter(|command| command.prefix_no) {
            let removed = catalog
                .validate(&command.path, HttpMethod::Post, &json!({"no":true}))
                .map_err(|issues| format!("{}: {issues:?}", command.path))?;
            assert_eq!(
                removed.risk,
                Risk::Destructive,
                "{version} {}",
                command.path
            );
            if let Ok(deleted) = catalog.validate(&command.path, HttpMethod::Delete, &json!({})) {
                assert_eq!(removed.risk, deleted.risk.max(Risk::Destructive));
            }
        }
        for line in [
            "no user victim",
            "no interface Bridge0",
            "no system hostname",
        ] {
            let removed = catalog
                .validate_cli(line, RawAuthorization::default())
                .map_err(|issues| format!("{line}: {issues:?}"))?;
            assert_eq!(removed.risk, Risk::Destructive, "{version} {line}");
        }
    }
    Ok(())
}

/// Destructive siblings never erase the independently recorded management requirement.
#[test]
fn mixed_requests_retain_management() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let body = json!({"ip":{"http":{"port":{"port":8082_u16}}},"mws":{"member":{"reboot":{}}}});
    let request = catalog
        .validate("", HttpMethod::Post, &body)
        .map_err(|issues| format!("{issues:?}"))?;
    assert_eq!(request.risk, Risk::Destructive);
    assert!(request.contains_management());
    Ok(())
}

/// A nonempty unclassified capture fails closed while the empty root stays read-only.
#[test]
fn unclassified_nonempty_capture_is_a_write() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let request =
        ValidatedRequest::capture(&catalog, "", HttpMethod::Post, json!({"unknown":{}}), false);
    assert_eq!(request.risk, Risk::Write);
    let empty = catalog
        .validate("", HttpMethod::Post, &json!({}))
        .map_err(|issues| format!("{issues:?}"))?;
    assert_eq!(empty.risk, Risk::Read);
    Ok(())
}

/// Concrete instance names remain arguments while management intent remains classified.
#[test]
fn concrete_cli_management_intents_are_preserved() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for line in [
            "ip http port 8082",
            "user victim",
            "interface Bridge0 ip address 192.0.2.1 255.255.255.0",
            "interface Bridge0 up",
            "interface Bridge0 down",
        ] {
            let request = catalog
                .validate_cli(line, RawAuthorization::default())
                .map_err(|issues| format!("{version} {line}: {issues:?}"))?;
            assert_eq!(request.risk, Risk::Management, "{version} {line}");
            assert!(request.contains_management());
        }
    }
    Ok(())
}

/// Ordinary writes stay `Write` without the management fact, including an interface
/// command that is neither an address nor up/down and a whole-path root key.
#[test]
fn ordinary_writes_carry_no_management() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    assert_eq!(catalog.risk("interface description"), Some(Risk::Write));
    let line = "interface Bridge0 description lab";
    let interface = catalog
        .validate_cli(line, RawAuthorization::default())
        .map_err(|issues| format!("{line}: {issues:?}"))?;
    assert_eq!(interface.risk, Risk::Write, "{line}");
    assert!(!interface.contains_management(), "{line}");
    for body in [
        json!({"system country":{"country":"DE"}}),
        json!({"system":{"description":{"description":"lab"}}}),
    ] {
        let request = catalog
            .validate("", HttpMethod::Post, &body)
            .map_err(|issues| format!("{body}: {issues:?}"))?;
        assert_eq!(request.risk, Risk::Write, "{body}");
        assert!(!request.contains_management(), "{body}");
    }
    Ok(())
}
