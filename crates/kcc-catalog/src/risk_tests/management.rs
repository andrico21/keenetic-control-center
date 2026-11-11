//! Curated management contracts, independently specified as catalog paths.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, RawAuthorization, Risk};

/// Literal domain intents: listeners, bridge topology, firewall ingress and accounts.
const MANAGEMENT: &[&str] = &[
    "user",
    "user tag",
    "user password plain",
    "interface up",
    "interface down",
    "interface ip address",
    "interface ip address dhcp",
    "interface ip access-group",
    "interface security-level",
    "interface include",
    "interface inherit",
    "ip http port",
    "ip http security-level",
    "ip http ssl enable",
    "ip http ssl port",
    "ip http ssl redirect",
    "ip http ssl acme get",
    "ip http ssl acme revoke",
    "ip http proxy",
    "ip http proxy upstream",
    "ip ssh",
    "ip ssh port",
    "ip ssh security-level",
    "ip telnet",
    "ip telnet port",
    "ip telnet security-level",
    "service http",
    "service ssh",
    "service telnet",
    "cloud control2 security-level",
    "access-list permit",
    "access-list deny",
    "access-list rule",
];

/// Every present curated intent retains Management through public raw validation.
#[test]
fn curated_management_paths_protect_all_raw_shapes() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for &path in MANAGEMENT {
            let Some(command) = catalog.lookup(path) else {
                continue;
            };
            for negative in [false, true] {
                if negative && !command.prefix_no {
                    continue;
                }
                let leaf = if negative {
                    json!({"no":true})
                } else {
                    json!({})
                };
                let expected = if negative {
                    Risk::Destructive
                } else {
                    Risk::Management
                };
                let nested = path
                    .split_whitespace()
                    .rev()
                    .fold(leaf.clone(), |child, word| json!({word:child}));
                for (prefix, body) in [(path, leaf.clone()), ("", nested), ("", json!({path:leaf}))]
                {
                    let request = catalog
                        .validate(prefix, HttpMethod::Post, &body)
                        .map_err(|issues| format!("{version} {path}: {issues:?}"))?;
                    assert_eq!(request.risk, expected, "{version} {path}: {body}");
                    assert!(request.contains_management(), "{version} {path}: {body}");
                }
            }
            if command.prefix_no {
                let deleted = catalog
                    .validate(path, HttpMethod::Delete, &json!({}))
                    .map_err(|issues| format!("DELETE {version} {path}: {issues:?}"))?;
                assert!(deleted.risk >= Risk::Management, "{version} {path}");
                assert!(deleted.contains_management(), "DELETE {version} {path}");
            }
        }
    }
    Ok(())
}

/// Explicit recovery operations require Destructive without auto-disarming their timer.
#[test]
fn raw_recovery_timer_control_is_destructive() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for path in [
            "system configuration fail-safe timer",
            "system configuration fail-safe keep-alive",
        ] {
            let request = catalog
                .validate(path, HttpMethod::Post, &json!({}))
                .map_err(|issues| format!("{version} {path}: {issues:?}"))?;
            assert_eq!(request.risk, Risk::Destructive, "{version} {path}");
            assert!(!request.contains_management(), "explicit timer lifecycle");
        }
    }
    Ok(())
}

/// CLI negation retains the recovery requirement independently of the destructive floor.
#[test]
fn raw_negative_management_line_keeps_bracket() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for line in [
        "no service http",
        "no interface Bridge0 ip access-group LabAcl in",
    ] {
        let request = catalog
            .validate_cli(line, RawAuthorization::default())
            .map_err(|issues| format!("{line}: {issues:?}"))?;
        assert_eq!(request.risk, Risk::Destructive, "{line}");
        assert!(request.contains_management(), "{line}");
    }
    Ok(())
}

/// IPv6 bindings are rejected until an embedded manual provides their command grammar.
#[test]
fn undocumented_ipv6_binding_fails_validation() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        let result = catalog.validate("interface ipv6 access-group", HttpMethod::Post, &json!({}));
        assert!(matches!(result, Err(issues) if !issues.is_empty()));
    }
    Ok(())
}
