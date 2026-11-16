//! CLI boundary regression tests against committed firmware catalogs.

use core::str::FromStr as _;

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, RawAuthorization, Risk, ValidationIssue};

/// Builds the same hardware view for both supported test firmware lines.
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures are valid"
)]
fn catalog(version: &str) -> Catalog {
    Catalog::for_firmware_and_model(
        FirmwareVersion::from_str(version).expect("valid firmware"),
        Some("KN-1811"),
    )
    .expect("valid embedded catalog")
}

/// Fixed forms preserve path, positional values, negative prefix, and risk.
#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn cli_fixed_forms_are_validated_in_both_firmware_views() {
    for version in ["4.3.9", "5.1.0"] {
        let current = catalog(version);
        for (line, path, value, risk) in [
            (
                "  system\thostname myrouter  ",
                "system hostname",
                json!({"hostname":"myrouter"}),
                Risk::Write,
            ),
            (
                "no system hostname",
                "system hostname",
                json!({"no":true}),
                Risk::Destructive,
            ),
            (
                "system configuration save",
                "system configuration save",
                json!({}),
                Risk::Write,
            ),
            (
                "system configuration factory-reset",
                "system configuration factory-reset",
                json!({}),
                Risk::Destructive,
            ),
            (
                "ip host myrouter.example 192.0.2.1",
                "ip host",
                json!({"domain":"myrouter.example","address":"192.0.2.1"}),
                Risk::Write,
            ),
            (
                "system configuration fail-safe timer reboot 60",
                "system configuration fail-safe timer",
                json!({"action":"reboot","interval":60_i64}),
                Risk::Destructive,
            ),
        ] {
            let request = current
                .validate_cli(line, RawAuthorization::default())
                .expect("fixed form validates");
            assert_eq!(request.path, path, "{line}");
            assert_eq!(request.method, HttpMethod::Post);
            assert_eq!(*request.value(), value, "{line}");
            assert_eq!(request.risk, risk, "{line}");
            assert!(!request.unvalidated, "{line}");
        }
    }
}

/// Known invalid scalar values never enter the raw escape even for administrators.
#[test]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn cli_reuses_scalar_validation() {
    let current = catalog("5.1.0");
    for (line, field) in [
        ("ip host myrouter.example invalid-ip", "address"),
        (
            "system configuration fail-safe timer reboot invalid-integer",
            "interval",
        ),
        (
            "system configuration fail-safe timer invalid-keyword 60",
            "action",
        ),
    ] {
        assert_eq!(
            current.validate_cli(
                line,
                RawAuthorization {
                    raw_rci: true,
                    admin_manage_routers: true
                }
            ),
            Err(vec![ValidationIssue::InvalidValue {
                field: field.to_owned()
            }])
        );
    }
}

/// Tokenization must not discard extra commands, quotes, or positional values.
#[test]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn cli_rejects_unsupported_token_syntax_and_wrong_arity() {
    let current = catalog("5.1.0");
    for line in [
        "",
        "  ",
        "no",
        "system hostname",
        "system hostname one two",
        "system hostname \"router\"",
        "system hostname router\nsystem reboot",
        "system configuration save extra",
        "system hostname a;reboot",
    ] {
        assert_eq!(
            current.validate_cli(line, RawAuthorization::default()),
            Err(vec![ValidationIssue::InvalidCliSyntax]),
            "{line}"
        );
    }
    assert_eq!(
        current.validate_cli("no system configuration save", RawAuthorization::default()),
        Err(vec![ValidationIssue::NoPrefixUnsupported])
    );
}

/// Optional and alternative multi-argument forms cannot be guessed from map order.
#[test]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn cli_rejects_ambiguous_synopsis_even_with_raw_authorization() {
    let current = catalog("5.1.0");
    assert_eq!(
        current.validate_cli(
            "system reboot 60",
            RawAuthorization {
                raw_rci: true,
                admin_manage_routers: true
            }
        ),
        Err(vec![ValidationIssue::UnsupportedCliSyntax {
            path: "system reboot".to_owned()
        }])
    );
}

/// Unknown command lines preserve their raw identity and require both privileges.
#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn cli_unknown_lines_use_existing_raw_gate() {
    let current = catalog("5.1.0");
    for line in ["future command value", "no future command value"] {
        for (raw_rci, admin_manage_routers) in [(false, false), (true, false), (false, true)] {
            assert_eq!(
                current.validate_cli(
                    line,
                    RawAuthorization {
                        raw_rci,
                        admin_manage_routers
                    }
                ),
                Err(vec![ValidationIssue::RawAuthorizationRequired])
            );
        }
        let request = current
            .validate_cli(
                line,
                RawAuthorization {
                    raw_rci: true,
                    admin_manage_routers: true,
                },
            )
            .expect("authorized raw line");
        assert!(request.unvalidated);
        assert_eq!(request.path, line);
        assert_eq!(*request.value(), json!({"command":line}));
        assert_eq!(request.risk, Risk::Management);
    }
}
