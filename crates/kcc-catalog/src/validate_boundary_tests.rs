//! Boundary tables for numeric, secret, type and method validation.
//!
//! No generated catalog argument carries `min`/`max`, and every `Password` argument is
//! also re-checked by the secret predicate, so the bound and Password checks are only
//! observable on the predicates themselves. The type, secret-path and method rules are
//! exercised through the public [`Catalog`] boundary.

#![expect(clippy::missing_panics_doc, reason = "a test fails by panicking")]

use core::str::FromStr as _;

use kcc_rci::version::FirmwareVersion;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{
    Argument, ArgumentKind, Catalog, HttpMethod, ValidationIssue,
    validate::{valid_argument, valid_secret},
};

/// Builds one synthetic argument with optional inclusive bounds.
fn argument(kind: ArgumentKind, minimum: Option<i64>, maximum: Option<i64>) -> Argument {
    Argument {
        name: "value".to_owned(),
        kind,
        values: Vec::new(),
        minimum,
        maximum,
    }
}

/// Opens the KN-1811 5.1 catalog view used by the public-boundary cases.
#[expect(clippy::expect_used, reason = "the embedded test catalog is valid")]
fn catalog() -> Catalog {
    Catalog::for_firmware_and_model(
        FirmwareVersion::from_str("5.1.0").expect("test firmware is valid"),
        Some("KN-1811"),
    )
    .expect("generated catalog is valid")
}

/// A printable ASCII string of exactly `length` bytes.
fn printable(length: usize) -> String {
    "s".repeat(length)
}

/// V1: integer bounds are inclusive and both ends are enforced.
#[test]
fn integer_bounds_are_inclusive() {
    let bounded = argument(ArgumentKind::Integer, Some(10), Some(20));
    let cases = [
        (json!(9_i64), false),
        (json!(10_i64), true),
        (json!(15_i64), true),
        (json!(20_i64), true),
        (json!(21_i64), false),
    ];
    for (value, expected) in cases {
        assert_eq!(valid_argument(&bounded, &value), expected, "{value}");
    }
}

/// V2: Password values are at most 256 bytes and contain no control character.
#[test]
fn password_length_and_control_characters() {
    let password = argument(ArgumentKind::Password, None, None);
    let cases = [
        (printable(256), true),
        (printable(257), false),
        ("line\nbreak".to_owned(), false),
        ("tab\tinside".to_owned(), false),
    ];
    for (text, expected) in cases {
        assert_eq!(
            valid_argument(&password, &Value::String(text.clone())),
            expected,
            "{} bytes",
            text.len()
        );
    }
}

/// V3: the secret predicate enforces length, control characters and argument bounds.
#[test]
fn secret_predicate_enforces_length_control_and_bounds() {
    let unbounded = argument(ArgumentKind::String, None, None);
    let bounded = argument(ArgumentKind::String, Some(8), Some(16));
    let cases = [
        (&unbounded, printable(256), true),
        (&unbounded, printable(257), false),
        (&unbounded, "bad\u{7}bell".to_owned(), false),
        (&bounded, printable(7), false),
        (&bounded, printable(8), true),
        (&bounded, printable(16), true),
        (&bounded, printable(17), false),
    ];
    for (secret_argument, text, expected) in cases {
        assert_eq!(
            valid_secret(secret_argument, &Value::String(text.clone())),
            expected,
            "{} bytes, bounds {:?}..{:?}",
            text.len(),
            secret_argument.minimum,
            secret_argument.maximum
        );
    }
}

/// V3: a String argument on a secret path is length- and control-checked at the boundary.
#[test]
fn secret_path_string_argument_is_checked_by_validate() {
    let catalog = catalog();
    let path = "interface wireguard obfs-key";
    for (text, accepted) in [
        (printable(256), true),
        (printable(257), false),
        ("obfs\rkey".to_owned(), false),
    ] {
        let result = catalog.validate(path, HttpMethod::Post, &json!({ "obfs-key": text }));
        match result {
            Ok(_request) => assert!(accepted, "{} bytes accepted", text.len()),
            Err(issues) => {
                assert!(!accepted, "{} bytes rejected", text.len());
                assert_eq!(
                    issues,
                    vec![ValidationIssue::InvalidValue {
                        field: "obfs-key".to_owned()
                    }]
                );
            }
        }
    }
}

/// V3: `validate_secret` refuses empty, overlong and control-bearing input and keeps valid input.
#[test]
fn validate_secret_refuses_out_of_range_input() {
    let catalog = catalog();
    let path = "user password plain";
    for (text, accepted) in [
        (String::new(), false),
        (printable(257), false),
        ("pass\u{0}word".to_owned(), false),
        (printable(256), true),
    ] {
        let length = text.len();
        let result = catalog.validate_secret(path, "password", SecretString::from(text));
        match result {
            Ok(request) => {
                assert!(accepted, "{length} bytes accepted");
                assert_eq!(request.value, json!({ "password": "<redacted>" }));
            }
            Err(issues) => {
                assert!(!accepted, "{length} bytes rejected");
                assert_eq!(
                    issues,
                    vec![ValidationIssue::InvalidValue {
                        field: "password".to_owned()
                    }]
                );
            }
        }
    }
}

/// V4: a non-secret Integer argument given a string is rejected.
#[test]
fn non_secret_argument_of_wrong_type_is_rejected() {
    let catalog = catalog();
    let path = "components validity-period";
    assert_eq!(
        catalog
            .validate(path, HttpMethod::Post, &json!({ "seconds": 3600_i64 }))
            .err(),
        None
    );
    assert_eq!(
        catalog
            .validate(path, HttpMethod::Post, &json!({ "seconds": "3600" }))
            .err(),
        Some(vec![ValidationIssue::InvalidValue {
            field: "seconds".to_owned()
        }])
    );
}

/// V5: `DELETE` is accepted only for a Setting that supports the `no` prefix.
#[test]
fn delete_requires_a_prefix_no_setting() {
    let catalog = catalog();
    let with_prefix_no = "components validity-period";
    let without_prefix_no = "cloud webui cdn";
    assert!(
        catalog
            .lookup(with_prefix_no)
            .is_some_and(|command| command.prefix_no)
    );
    assert!(
        catalog
            .lookup(without_prefix_no)
            .is_some_and(|command| !command.prefix_no)
    );
    assert_eq!(
        catalog
            .validate(with_prefix_no, HttpMethod::Delete, &json!({}))
            .err(),
        None
    );
    assert_eq!(
        catalog
            .validate(without_prefix_no, HttpMethod::Delete, &json!({}))
            .err(),
        Some(vec![ValidationIssue::MethodNotAllowed {
            method: HttpMethod::Delete
        }])
    );
}
