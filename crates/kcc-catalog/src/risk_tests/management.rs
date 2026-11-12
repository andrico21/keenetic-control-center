//! Curated management contracts, independently specified as catalog paths.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, CommandKind, HttpMethod, RawAuthorization, Risk};

/// Literal domain intents: listeners, bridge topology, firewall ingress and accounts.
const MANAGEMENT: &[&str] = &[
    "interface",
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
    "interface role",
    "interface ipv6 address",
    "interface ip dhcp client routes",
    "interface ip global",
    "interface mac address",
    "interface mac clone",
    "ip route",
    "system mode",
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

/// Raw writes that do not alter the router's management return path.
const ORDINARY: &[&str] = &[
    "interface description",
    "interface rf",
    "interface mac band",
    "ip hotspot default-policy",
    "ip hotspot policy",
    "dns-proxy filter assign interface profile",
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
            if command.kind == CommandKind::Setting && command.prefix_no {
                let delete_value = if path == "interface" {
                    json!({"name":"sample"})
                } else {
                    json!({})
                };
                let deleted = catalog
                    .validate(path, HttpMethod::Delete, &delete_value)
                    .map_err(|issues| format!("DELETE {version} {path}: {issues:?}"))?;
                assert!(deleted.risk >= Risk::Management, "{version} {path}");
                assert!(deleted.contains_management(), "DELETE {version} {path}");
            }
        }
    }
    Ok(())
}

/// The explicit reachability table keeps ordinary raw work available to raw writers.
#[test]
fn reachability_candidates_have_reasoned_risk() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for &path in ORDINARY {
            if catalog.lookup(path).is_none() {
                continue;
            }
            assert_eq!(catalog.risk(path), Some(Risk::Write), "{version} {path}");
        }
    }
    Ok(())
}

/// Name-keyed ordinary leaves use their own risk instead of the interface ancestor's risk.
#[test]
fn ordinary_name_keyed_interface_leaves_remain_write() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for value in [
        json!({"interface":{"name":"GigabitEthernet0/0","description":{"description":"lab"}}}),
        json!({"interface":{"name":"WifiMaster0/AccessPoint1","ssid":{"ssid":"lab"}}}),
        json!({"interface":{"name":"WifiMaster0/AccessPoint1","rf":{}}}),
        json!({"interface":{"name":"WifiMaster0/AccessPoint1","mac":{"band":{"mac":"02:00:00:00:00:01","band":"0"}}}}),
    ] {
        let request = catalog
            .validate("", HttpMethod::Post, &value)
            .map_err(|issues| format!("{value}: {issues:?}"))?;
        assert_eq!(request.risk, Risk::Write, "{value}");
        assert!(!request.contains_management(), "{value}");
    }
    Ok(())
}

/// A schedule can disable the management access point, so both raw spellings fail closed.
#[test]
fn raw_interface_schedule_requires_recovery_in_both_spellings() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let line = catalog
        .validate_cli(
            "interface WifiMaster0/AccessPoint0 schedule sample",
            RawAuthorization::default(),
        )
        .map_err(|issues| format!("schedule line: {issues:?}"))?;
    let structured = catalog
        .validate(
            "",
            HttpMethod::Post,
            &json!({"interface":{"name":"WifiMaster0/AccessPoint0","schedule":{"schedule":"sample"}}}),
        )
        .map_err(|issues| format!("schedule body: {issues:?}"))?;
    for request in [line, structured] {
        assert_eq!(request.risk, Risk::Management);
        assert!(request.contains_management());
    }
    Ok(())
}

/// Whole-interface removal and operating-mode changes retain Management in every spelling.
#[test]
fn interface_removal_and_mode_switch_require_recovery() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for (path, method, value) in [
        (
            "interface",
            HttpMethod::Post,
            json!({"name":"Bridge0","no":true}),
        ),
        ("interface", HttpMethod::Delete, json!({"name":"Bridge0"})),
        ("system mode", HttpMethod::Post, json!({"mode":"extender"})),
    ] {
        let request = catalog
            .validate(path, method, &value)
            .map_err(|issues| format!("{method:?} {path}: {issues:?}"))?;
        assert!(request.risk >= Risk::Management, "{method:?} {path}");
        assert!(request.contains_management(), "{method:?} {path}");
    }
    for line in ["no interface Bridge0", "system mode EXTENDER"] {
        let request = catalog
            .validate_cli(line, RawAuthorization::default())
            .map_err(|issues| format!("{line}: {issues:?}"))?;
        assert!(request.risk >= Risk::Management, "{line}");
        assert!(request.contains_management(), "{line}");
    }
    Ok(())
}

/// Interface identity semantics survive sibling leaves in every structured spelling.
#[test]
fn interface_identity_with_siblings_requires_recovery() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    for (path, method, value) in [
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
            "",
            HttpMethod::Post,
            json!({"interface":{"name":"Bridge0","no":true,"ip":{"mtu":{"mtu":1_500_i32}}}}),
        ),
        (
            "interface",
            HttpMethod::Delete,
            json!({"name":"Bridge0","description":{"description":"lab"}}),
        ),
    ] {
        let request = catalog
            .validate(path, method, &value)
            .map_err(|issues| format!("{method:?} {path} {value}: {issues:?}"))?;
        assert!(
            request.risk >= Risk::Management,
            "{method:?} {path} {value}"
        );
        assert!(request.contains_management(), "{method:?} {path} {value}");
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
