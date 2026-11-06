//! Seed fixtures compiled into the crate, one set per model.
//!
//! Each model has a 5.1 seed. Older profiles remove documented JSON pointers, then all
//! profiles receive deterministic synthetic domain fixtures.

mod synthetic;

use serde_json::{Map, Value};

use crate::{
    model::{Firmware, Model, Profile},
    tree,
};

/// Initial settings, show responses, and startup configuration of one profile.
pub(crate) type Fixtures = (Value, Map<String, Value>, &'static str);

/// Returns model-specific settings and show seed texts.
const fn seed(model: Model) -> (&'static str, &'static str) {
    match model {
        Model::Kn1811 => (
            include_str!("../fixtures/KN-1811/settings.json"),
            include_str!("../fixtures/KN-1811/show.json"),
        ),
        Model::Kn1010 => (
            include_str!("../fixtures/KN-1010/settings.json"),
            include_str!("../fixtures/KN-1010/show.json"),
        ),
        Model::Kn3810 => (
            include_str!("../fixtures/KN-3810/settings.json"),
            include_str!("../fixtures/KN-3810/show.json"),
        ),
        Model::Nc3013 => (
            include_str!("../fixtures/NC-3013/settings.json"),
            include_str!("../fixtures/NC-3013/show.json"),
        ),
    }
}

/// Returns the startup configuration seed of a model.
const fn startup(model: Model) -> &'static str {
    match model {
        Model::Kn1811 => include_str!("../fixtures/KN-1811/startup-config.txt"),
        Model::Kn1010 => include_str!("../fixtures/KN-1010/startup-config.txt"),
        Model::Kn3810 => include_str!("../fixtures/KN-3810/startup-config.txt"),
        Model::Nc3013 => include_str!("../fixtures/NC-3013/startup-config.txt"),
    }
}

/// Returns the removal list of a documentation-derived firmware line.
const fn derived(firmware: Firmware) -> Option<&'static str> {
    match firmware {
        Firmware::V4_3 => Some(include_str!("../fixtures/derived/4.3.json")),
        Firmware::V5_0 => Some(include_str!("../fixtures/derived/5.0.json")),
        Firmware::V5_1 => None,
    }
}

/// Removes every pointer listed under `key` from `target`.
fn strip(target: &mut Value, removals: &Value, key: &str) {
    for pointer in removals
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let _: bool = tree::remove(target, pointer);
    }
}

/// Loads one profile and applies firmware removals plus synthetic domain fixtures.
///
/// # Errors
///
/// Returns a parse error when an embedded fixture is malformed.
pub(crate) fn load(
    profile: Profile,
    title: &str,
    release: &str,
) -> Result<Fixtures, serde_json::Error> {
    let (settings_text, show_text) = seed(profile.model());
    let mut settings: Value = serde_json::from_str(settings_text)?;
    let mut show: Value = serde_json::from_str(show_text)?;
    if let Some(removals_text) = derived(profile.firmware()) {
        let removals: Value = serde_json::from_str(removals_text)?;
        strip(&mut settings, &removals, "settings");
        strip(&mut show, &removals, "show");
    }
    if let Some(version) = show.get_mut("version").and_then(Value::as_object_mut) {
        drop(version.insert("title".to_owned(), Value::from(title)));
        drop(version.insert("release".to_owned(), Value::from(release)));
    }
    synthetic::enrich(&mut show, profile.model());
    let show_map = match show {
        Value::Object(map) => map,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Map::new()
        }
    };
    Ok((settings, show_map, startup(profile.model())))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use serde_json::Value;

    use super::load;
    use crate::model::{Firmware, Model, Profile};

    /// Every profile loads and derived lines lose their unsupported ACL.
    #[test]
    fn every_profile_loads() -> Result<(), Box<dyn Error>> {
        for model in Model::ALL {
            for &firmware in model.firmware_lines() {
                let (settings, show, startup) = load(Profile::new(model, firmware)?, "t", "r")?;
                let has_acl = settings.pointer("/ipv6/access-list").is_some();
                assert_eq!(has_acl, firmware == Firmware::V5_1, "{model} {firmware}");
                assert_eq!(
                    show.get("version").and_then(|version| version.get("hw_id")),
                    Some(&Value::from(model.hw_id()))
                );
                assert!(startup.contains("192.0.2.1"));
            }
        }
        Ok(())
    }
}
