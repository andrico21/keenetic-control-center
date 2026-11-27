//! The firmware's vocabulary in the anonymizer.
//!
//! A value equal to a firmware word is neither aliased nor learned, a learned value never
//! alters a firmware key or keyword, and a short learned value is replaced only as a whole
//! word.
//!
//! Assertion messages never carry a planted value.

use serde_json::json;
use zeroize::Zeroizing;

use super::{Anonymizer, fold, vocabulary::Vocabulary};

/// An anonymizer with a fixed key and `words` as the firmware's vocabulary.
fn with_words(words: &[&str]) -> Anonymizer {
    Anonymizer::from_key(Zeroizing::new([7_u8; 64])).with_vocabulary(Vocabulary::new(words))
}

/// A client named like a row field, a user and an SSID named like firmware keywords keep
/// their names, are not learned and leave the schema intact; other names are still aliased
/// and learned (todo 12).
///
/// # Panics
///
/// Panics when a firmware word is aliased or learned, or a planted name is not.
#[test]
fn a_value_equal_to_a_firmware_word_is_neither_aliased_nor_learned() {
    let mut anonymizer = with_words(&["uptime", "service", "interface", "hostname"]);
    let rows = json!({"host": [{"name": "Uptime", "hostname": "PLANTED-HOST-7", "uptime": 5_u8}]});
    let users = json!({"user": {"service": {"tag": ["cli"]}, "PLANTED-USER-13": {}}});
    let config = "interface WifiMaster0/AccessPoint0\n    ssid interface\n!\n";
    for _pass in 0..2_u8 {
        assert!(anonymizer.json(&rows).is_ok(), "rows anonymize");
        assert!(anonymizer.json(&users).is_ok(), "users anonymize");
        assert!(anonymizer.config(config).is_ok(), "config anonymizes");
    }
    assert_eq!(
        anonymizer.json(&rows).ok(),
        Some(json!({"host": [{"name": "Uptime", "hostname": "host-1", "uptime": 5_u8}]})),
        "the row keeps its schema and the firmware-word name"
    );
    assert_eq!(
        anonymizer.json(&users).ok(),
        Some(json!({"user": {"service": {"tag": ["cli"]}, "user-1": {}}})),
        "a user named like a keyword keeps its key"
    );
    let printed = anonymizer.config(config).unwrap_or_default();
    assert!(
        printed.lines().any(|line| line.trim() == "ssid interface"),
        "an SSID named like a keyword is kept"
    );
    let identifiers = anonymizer.identifiers();
    for word in ["uptime", "service", "interface"] {
        assert!(
            identifiers
                .iter()
                .all(|found| fold::fold(&found.value) != word),
            "a firmware word was learned"
        );
    }
    for planted in ["PLANTED-HOST-7", "PLANTED-USER-13"] {
        assert!(
            identifiers.iter().any(|found| found.value == planted),
            "a planted name was not learned"
        );
    }
}

/// A learned value, short or long, never alters a key outside a name-keyed map, not even a
/// whole key equal to it, nor a longer word; in text and as a map entry's name it is still
/// replaced (todo 12).
///
/// # Panics
///
/// Panics when a firmware key changes or a learned value survives in text or a map.
#[test]
fn a_learned_value_never_alters_a_firmware_key() {
    let mut anonymizer = with_words(&["hostname", "name-servers", "host-only"]);
    let learning = json!([{"name": "Host"}, {"description": "servers"}, {"name": "Release"}]);
    assert!(anonymizer.json(&learning).is_ok(), "learning pass");
    let document = json!({
        "hostname": true, "name-servers": ["b"], "host-only": true, "Hostx": 1_u8, "Host": 2_u8,
        "release": 3_u8, "known": {"host": {"Release": {"priority": 1_u8}}},
        "note": "Host lookup; Hostx and hostname kept",
    });
    assert_eq!(
        anonymizer.json(&document).ok(),
        Some(json!({
            "hostname": true, "name-servers": ["b"], "host-only": true, "Hostx": 1_u8, "Host": 2_u8,
            "release": 3_u8, "known": {"host": {"host-3": {"priority": 1_u8}}},
            "note": "host-1 lookup; Hostx and hostname kept",
        })),
        "keys are kept, values and map names replaced"
    );
}

/// A learned value shorter than six characters is replaced only as a whole word, in its
/// exact spelling too; a longer one anywhere (todo 12).
///
/// # Panics
///
/// Panics when a short value is replaced inside a word or a whole one survives.
#[test]
fn a_short_value_is_replaced_only_as_a_whole_word_in_any_spelling() {
    let learned: Vec<fold::Learned<'_>> = [("Planted", "host-2"), ("Mama", "host-1")]
        .into_iter()
        .filter_map(|(original, replacement)| fold::Learned::new(original, replacement))
        .collect();
    assert_eq!(
        fold::replace_all_except(
            "MamaPhone Mama-pc xMama Mama. (mama) xPlantedy",
            &learned,
            |_| false
        ),
        "MamaPhone Mama-pc xMama host-1. (host-1) xhost-2y",
        "short values only whole, long ones anywhere"
    );
}

/// A learned value never alters a configuration keyword, neither as a word nor in the
/// whole-text pass; a learned value of several words that holds a keyword is still
/// replaced (todo 12).
///
/// # Panics
///
/// Panics when a keyword changes or a learned value survives.
#[test]
fn a_learned_value_never_alters_a_configuration_keyword() {
    let mut anonymizer = with_words(&["ip", "name-server", "route", "auto"]);
    let learning = json!([{"name": "server"}, {"comment": "Office route"}]);
    assert!(anonymizer.json(&learning).is_ok(), "learning pass");
    let config = "ip name-server 192.0.2.53\n\
                  ip route 192.0.2.0 255.255.255.0 Bridge0 auto !Office route\n\
                  ip route 198.51.100.0 255.255.255.0 Bridge0 auto !server\n";
    let printed = anonymizer.config(config).unwrap_or_default();
    let lines: Vec<&str> = printed.lines().map(str::trim).collect();
    assert!(
        lines.iter().any(|line| line.starts_with("ip name-server ")),
        "the keyword is kept"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("ip route ") && line.ends_with(" auto !host-2")),
        "a learned value of several words is replaced"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("ip route ") && line.ends_with(" auto !host-1")),
        "a whole learned word is replaced"
    );
}

/// A secret equal to a vocabulary word is still redacted, in JSON and in a configuration
/// (todo 12).
///
/// # Panics
///
/// Panics when a secret survives.
#[test]
fn a_secret_equal_to_a_vocabulary_word_is_still_redacted() {
    let mut anonymizer = with_words(&["interface", "hostname", "name"]);
    let secrets = json!({"psk": "interface", "password": {"md5": "hostname"}, "key": "name"});
    assert_eq!(
        anonymizer.json(&secrets).ok(),
        Some(json!({"psk": "<redacted>", "password": {"md5": "<redacted>"}, "key": "<redacted>"})),
        "every secret is redacted"
    );
    let printed = anonymizer
        .config("user admin\n    password md5 hostname\n!\n")
        .unwrap_or_default();
    assert!(
        printed
            .lines()
            .any(|line| line.trim() == "password md5 <redacted>"),
        "a configuration secret is redacted"
    );
}

/// A serial equal to a vocabulary word is replaced and learned, so it is replaced in text
/// too (todo 12).
///
/// # Panics
///
/// Panics when the serial survives or is not learned.
#[test]
fn a_serial_equal_to_a_vocabulary_word_is_replaced_and_learned() {
    let mut anonymizer = with_words(&["uptime"]);
    assert_eq!(
        anonymizer.json(&json!({"serial": "uptime"})).ok(),
        Some(json!({"serial": "000000"})),
        "the serial is zeroed"
    );
    assert!(
        anonymizer
            .identifiers()
            .iter()
            .any(|found| found.value == "uptime"),
        "the serial is not learned"
    );
    assert_eq!(
        anonymizer.text("device uptime ready").ok().as_deref(),
        Some("device 000000 ready"),
        "the serial is replaced in text"
    );
}

/// A dash-spelled MAC and a host label holding a dashed IPv4 address are never vocabulary
/// words: the text rules would rewrite them (todo 12).
///
/// # Panics
///
/// Panics when either is admitted.
#[test]
fn words_the_text_rules_rewrite_are_never_vocabulary() {
    let mac = format!("ab-cd-ef-{}", "01-02-03");
    let label = format!("pc-{}-0-2-10", 192_u8);
    let vocabulary = Vocabulary::new([mac.as_str(), label.as_str()]);
    assert!(
        !vocabulary.holds(&mac) && !vocabulary.holds(&label),
        "a rewritten word is admitted"
    );
    assert!(vocabulary.is_empty(), "the vocabulary is empty");
}
