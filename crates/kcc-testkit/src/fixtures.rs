//! Seed fixtures compiled into the crate, one set per model.
//!
//! Each model has a 5.1 seed: `fixtures/<hw_id>/settings.json` (the settings tree) and
//! `fixtures/<hw_id>/show.json` (show responses keyed by RCI path below `show/`). The
//! 4.3 and 5.0 profiles start from the same seed and drop the JSON pointers listed in
//! `fixtures/derived/<line>.json`.

use serde_json::{Map, Value};

use crate::{
    model::{Firmware, Model, Profile},
    tree,
};

/// The initial settings tree and the show responses keyed by the path below `show/`
/// (e.g. `clock/date`) of one profile.
pub(crate) type Fixtures = (Value, Map<String, Value>);

/// The `(settings, show)` seed texts of a model.
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

/// The removal list of a documentation-derived firmware line.
const fn derived(firmware: Firmware) -> Option<&'static str> {
    match firmware {
        Firmware::V4_3 => Some(include_str!("../fixtures/derived/4.3.json")),
        Firmware::V5_0 => Some(include_str!("../fixtures/derived/5.0.json")),
        Firmware::V5_1 => None,
    }
}

/// Removes every pointer listed under `key` in `removals` from `target`.
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

/// Loads the fixtures of `profile`, reporting `title` and `release` in `show version`.
///
/// # Errors
///
/// A parse error of an embedded fixture.
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
    let show_map = match show {
        Value::Object(map) => map,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Map::new()
        }
    };
    Ok((settings, show_map))
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

    use super::load;
    use crate::model::{Firmware, Model, Profile};

    /// Every profile loads; derived lines lose `ipv6 access-list`, 5.1 keeps it.
    #[test]
    fn every_profile_loads() -> Result<(), Box<dyn Error>> {
        for model in Model::ALL {
            for &firmware in model.firmware_lines() {
                let (settings, show) = load(Profile::new(model, firmware)?, "t", "r")?;
                let has_acl = settings.pointer("/ipv6/access-list").is_some();
                assert_eq!(has_acl, firmware == Firmware::V5_1, "{model} {firmware}");
                assert_eq!(
                    show.get("version").and_then(|version| version.get("hw_id")),
                    Some(&serde_json::Value::from(model.hw_id()))
                );
            }
        }
        Ok(())
    }
}
