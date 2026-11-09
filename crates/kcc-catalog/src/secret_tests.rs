//! Secret request ownership tests against the actual firmware catalog.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use proptest::{
    prelude::proptest,
    test_runner::{Config, RngSeed, TestCaseError},
};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::{Catalog, HttpMethod, SecretValue, ValidationIssue};

proptest! {
    #![proptest_config(Config { cases: 256, rng_seed: RngSeed::Fixed(17), ..Config::default() })]
    /// Debug and serialization must hide values while the wire body retains them.
    #[test]
    fn secret_body_has_only_explicit_plaintext_access(secret in "[^\\p{Cc}]{1,256}") {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        let result = catalog.validate("user password plain", HttpMethod::Post, &json!({"password":secret}));
        if secret.len() > 256 {
            assert!(matches!(result, Err(issues) if issues == vec![ValidationIssue::InvalidValue { field: "password".to_owned() }]), "overlong secret must fail without retaining input");
        } else {
            let request = result.map_err(|_issues| TestCaseError::fail("valid secret refused"))?;
            assert_eq!(request.value, json!({"password":"<redacted>"}));
            let serialized = serde_json::to_value(&request)?;
            assert_eq!(serialized.pointer("/value/password"), Some(&Value::String("<redacted>".to_owned())));
            let debug = format!("{request:?}");
            let changed = catalog.validate("user password plain", HttpMethod::Post, &json!({"password":"another-fixture-secret"})).map_err(|_issues| TestCaseError::fail("fixture refused"))?;
            assert_eq!(debug, format!("{changed:?}"), "Debug must be independent of secret material");
            let wire = request.expose_for_send();
            assert!(wire.expose_secret().get("password").and_then(Value::as_str) == Some(secret.as_str()), "wire accessor must preserve input");
            assert_eq!(request.protected_value().scrub_text(&format!("router echoed {secret}")), "router echoed <redacted>");
        }
    }
}

/// Root objects use the same secret pointers as direct command validation.
#[test]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions define the ownership contract"
)]
fn nested_secret_is_redacted() -> Result<(), Box<dyn Error>> {
    let catalog =
        Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
    let request = catalog
        .validate(
            "",
            HttpMethod::Post,
            &json!({"user":{"password":{"plain":{"password":"nested-fixture"}}}}),
        )
        .map_err(|_issues| "fixture refused")?;
    assert_eq!(
        request.value.pointer("/user/password/plain/password"),
        Some(&json!("<redacted>"))
    );
    assert_eq!(
        request
            .protected_value()
            .secret_pointers()
            .collect::<Vec<_>>(),
        vec!["/user/password/plain/password"]
    );
    Ok(())
}

/// Both obfuscation-key commands protect String-typed catalog arguments.
#[test]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions define the ownership contract"
)]
fn obfuscation_keys_are_redacted() -> Result<(), Box<dyn Error>> {
    let catalog =
        Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
    for path in [
        "interface wireguard obfs-key",
        "interface wireguard peer obfs-key",
    ] {
        let request = catalog
            .validate(
                path,
                HttpMethod::Post,
                &json!({"obfs-key":"obfuscation-fixture"}),
            )
            .map_err(|_issues| "fixture refused")?;
        assert_eq!(request.value, json!({"obfs-key":"<redacted>"}));
        assert!(!format!("{request:?}").contains("obfuscation-fixture"));
        assert_eq!(
            request
                .protected_value()
                .scrub_text("echo obfuscation-fixture"),
            "echo <redacted>"
        );
        assert!(
            request
                .expose_for_send()
                .expose_secret()
                .get("obfs-key")
                .and_then(Value::as_str)
                == Some("obfuscation-fixture"),
            "wire accessor must preserve the secret"
        );
    }
    Ok(())
}

/// Equality covers the retained scrubbers: two values that remove different text from
/// router output are different values.
#[test]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions define the ownership contract"
)]
fn equality_compares_retained_scrubbers() {
    let plain = SecretValue::new("system description", json!({"description": "lab"}));
    let mut scrubbed = plain.clone();
    scrubbed.retain_scrubber(SecretString::from("scrubber-fixture"));
    let mut same = plain.clone();
    same.retain_scrubber(SecretString::from("scrubber-fixture"));
    let mut other = plain.clone();
    other.retain_scrubber(SecretString::from("other-fixture"));
    assert_ne!(plain, scrubbed, "a scrubber makes a difference");
    assert_ne!(scrubbed, other, "the scrubber text makes a difference");
    assert_eq!(scrubbed, same);
}
