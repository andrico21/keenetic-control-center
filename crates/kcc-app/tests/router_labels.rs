//! Router display names: the one validation rule, `kcc.toml` and `routers.json` forms,
//! and the registry's display name.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration-test assertions and fixture filesystem setup"
)]

use core::error::Error;
use std::fs;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RegistryError, RouterRegistry, label},
    settings::{Config, ConfigError, OutboundConfig},
};
use tempfile::TempDir;
use url::Url;

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// `routers.json` exactly as kcc 1.0.0 writes one password profile without a label.
const STORED_1_0_0: &str = r#"{
  "routers": [
    {
      "id": "r1",
      "login": "admin",
      "password_file": "/etc/kcc/r1.pw",
      "read_login": null,
      "read_password_file": null,
      "tags": [],
      "test_device": false,
      "tls": "verify",
      "url": "http://192.0.2.10/"
    }
  ],
  "schema": 1
}
"#;

/// A Cyrillic display name with spaces.
const CYRILLIC: &str = "\u{414}\u{430}\u{447}\u{430} \u{443} \u{43e}\u{437}\u{435}\u{440}\u{430}";

/// The Cyrillic letter `zhe`.
const ZHE: &str = "\u{436}";

/// An administrator on every router.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// The password profile `r1` of [`STORED_1_0_0`].
fn profile() -> Result<ManagedRouterProfile, Box<dyn Error>> {
    Ok(ManagedRouterProfile::new(
        "r1".to_owned(),
        Url::parse("http://192.0.2.10")?,
        "admin".to_owned(),
        "/etc/kcc/r1.pw".into(),
    ))
}

/// Todo 7: names are trimmed, blank means none, any script and inner spaces pass, and a
/// control character or a 65th character is refused.
#[test]
fn label_rule_trims_and_refuses_control_characters_and_length() {
    assert_eq!(
        label::parse("  Home Office "),
        Ok(Some("Home Office".to_owned()))
    );
    assert_eq!(label::parse(CYRILLIC), Ok(Some(CYRILLIC.to_owned())));
    assert_eq!(label::parse(" \t "), Ok(None));
    let longest = ZHE.repeat(64);
    assert_eq!(label::parse(&longest), Ok(Some(longest.clone())));
    assert_eq!(label::parse(&ZHE.repeat(65)), Err(label::Fault::TooLong));
    assert_eq!(label::parse("Home\u{7}Office"), Err(label::Fault::Control));
    assert_eq!(label::parse("Home\nOffice"), Err(label::Fault::Control));
}

/// Todo 7: a `[[routers]]` entry parses with and without `label`; a blank one means none
/// and one with a control character is refused, naming the key.
#[test]
fn config_router_label_is_optional_and_checked() -> TestResult {
    let entry = |extra: &str| {
        format!(
            "[[routers]]\nname = \"r1\"\nurl = \"http://192.0.2.10\"\nlogin = \"admin\"\npassword_file = \"/etc/kcc/r1.pw\"\n{extra}"
        )
    };
    let plain = Config::from_toml_str(&entry(""))?;
    plain.validate()?;
    let named = Config::from_toml_str(&entry("label = \"Home Office\"\n"))?;
    named.validate()?;
    let labels = [&plain, &named].map(|config| config.routers.first().map(|router| &router.label));
    assert_eq!(labels, [Some(&None), Some(&Some("Home Office".to_owned()))]);

    let directory = TempDir::new()?;
    let store = StateStore::open(&directory.path().join("state"))?;
    let blank = Config::from_toml_str(&entry("label = \"   \"\n"))?;
    blank.validate()?;
    let registry = RouterRegistry::new(store, &blank.routers, &OutboundConfig::default())?;
    assert_eq!(registry.get("r1")?.profile.label, None);
    assert_eq!(registry.display_name("r1"), "r1");

    match Config::from_toml_str(&entry("label = \"a\\u0007b\"\n"))?.validate() {
        Err(ConfigError::Invalid { field, reason: _ }) => assert_eq!(field, "routers.r1.label"),
        other => return Err(format!("control character accepted: {other:?}").into()),
    }
    Ok(())
}

/// Todo 7: a `routers.json` written by 1.0.0 loads, and a profile saved without a label
/// is written byte for byte in that form, with no `label` key.
#[tokio::test]
async fn unlabelled_profile_keeps_the_1_0_0_state_form() -> TestResult {
    let directory = TempDir::new()?;
    let state = directory.path().join("state");
    let registry = RouterRegistry::new(StateStore::open(&state)?, &[], &OutboundConfig::default())?;

    registry.create(&admin(), profile()?).await?;

    assert_eq!(
        fs::read_to_string(state.join("routers.json"))?,
        STORED_1_0_0
    );
    let reopened = RouterRegistry::new(StateStore::open(&state)?, &[], &OutboundConfig::default())?;
    assert_eq!(reopened.get("r1")?.profile, profile()?);
    assert_eq!(reopened.display_name("r1"), "r1");
    Ok(())
}

/// Todo 7: a label survives a reload and becomes the display name; an unknown id is its
/// own display name; a stored label the rule refuses fails the load naming `label`.
#[tokio::test]
async fn stored_label_round_trips_and_names_the_router() -> TestResult {
    let directory = TempDir::new()?;
    let state = directory.path().join("state");
    let registry = RouterRegistry::new(StateStore::open(&state)?, &[], &OutboundConfig::default())?;
    let mut named = profile()?;
    named.label = Some(CYRILLIC.to_owned());

    registry.create(&admin(), named.clone()).await?;

    let reopened = RouterRegistry::new(StateStore::open(&state)?, &[], &OutboundConfig::default())?;
    assert_eq!(reopened.get("r1")?.profile, named);
    assert_eq!(reopened.display_name("r1"), CYRILLIC);
    assert_eq!(reopened.display_name("r2"), "r2");

    let broken = fs::read_to_string(state.join("routers.json"))?.replace(CYRILLIC, "a\\u0007b");
    fs::write(state.join("routers.json"), broken)?;
    match RouterRegistry::new(StateStore::open(&state)?, &[], &OutboundConfig::default()) {
        Err(RegistryError::InvalidProfile { reason }) => {
            assert!(reason.starts_with("label"), "reason: {reason}");
        }
        Err(other) => return Err(format!("unexpected error: {other}").into()),
        Ok(_registry) => return Err("a control character in a stored label loaded".into()),
    }
    Ok(())
}

/// Todo 7: a hand-written `routers.json` whose label is untrimmed, blank or empty is
/// refused as an invalid `label`, while the canonical label loads.
#[test]
fn stored_label_must_already_be_canonical() -> TestResult {
    let stored = |label: &str| {
        STORED_1_0_0.replace(
            "\"id\": \"r1\",\n",
            &format!("\"id\": \"r1\",\n      \"label\": \"{label}\",\n"),
        )
    };
    let load = |label: &str| -> Result<RouterRegistry, RegistryError> {
        let directory = TempDir::new().map_err(|error| RegistryError::InvalidProfile {
            reason: error.to_string(),
        })?;
        let state = directory.path().join("state");
        let store = StateStore::open(&state)?;
        fs::write(state.join("routers.json"), stored(label)).map_err(|error| {
            RegistryError::InvalidProfile {
                reason: error.to_string(),
            }
        })?;
        RouterRegistry::new(store, &[], &OutboundConfig::default())
    };

    let canonical = load("Home Office")?;
    assert_eq!(canonical.display_name("r1"), "Home Office");
    for refused in ["  Home Office ", "   ", ""] {
        match load(refused) {
            Err(RegistryError::InvalidProfile { reason }) => {
                assert!(reason.starts_with("label"), "{refused:?}: {reason}");
            }
            Err(other) => return Err(format!("{refused:?}: unexpected error: {other}").into()),
            Ok(_registry) => return Err(format!("{refused:?} loaded").into()),
        }
    }
    Ok(())
}
