//! Assumed running-configuration projection of the `opkg` settings and the DNS filter engine.

use serde_json::{Map, Value, json};

use super::{insert_path, matching};

/// Adds `opkg` (each setting shaped by its catalog argument names) and the DNS proxy's
/// `filter/engine`, after the other `dns-proxy` fields are in place.
pub(super) fn extend(root: &mut Map<String, Value>, lines: &[Vec<String>]) {
    let mut opkg = Map::new();
    for words in matching(lines, &["opkg"]) {
        let (name, value) = match words {
            [setting, disk] if setting == "disk" => (setting, json!({"disk":disk})),
            [setting, disk, url] if setting == "disk" => (setting, json!({"disk":disk,"url":url})),
            [setting, path] if setting == "initrc" => (setting, json!({"path":path})),
            [setting, zone] if setting == "timezone" && zone == "auto" => {
                (setting, json!({"auto":true}))
            }
            [setting, zone] if setting == "timezone" => (setting, json!({"timezone":zone})),
            [setting] if setting == "chroot" || setting == "dns-override" => (setting, json!(true)),
            _ => continue,
        };
        drop(opkg.insert(name.clone(), value));
    }
    insert_path(root, &["opkg"], Value::Object(opkg));
    if let Some(engine) =
        matching(lines, &["dns-proxy", "filter", "engine"]).find_map(|words| words.first())
    {
        insert_path(root, &["dns-proxy", "filter", "engine"], json!(engine));
    }
}
