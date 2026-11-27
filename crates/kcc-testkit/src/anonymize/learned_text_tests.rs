//! Learned values that span several configuration words, and interface references whose
//! id and name the firmware assigns.
//!
//! Assertion messages never carry a planted value.

use kcc_config::config_text;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::Anonymizer;
use crate::anonymize::fold::fold;

/// An anonymizer with a fixed key, so failures reproduce.
fn fixed() -> Anonymizer {
    Anonymizer::from_key(Zeroizing::new([7_u8; 64]))
}

/// The planted two-word route comment.
const COMMENT: &str = "Planted Route Note";

/// An anonymizer that learned [`COMMENT`] from an rci root answer.
///
/// # Panics
///
/// Panics when the learning pass fails.
fn learned_comment() -> Anonymizer {
    let mut anonymizer = fixed();
    let root = json!({"ip": {"route": [{"network": "0.0.0.0", "comment": COMMENT}]}});
    assert!(anonymizer.json(&root).is_ok(), "learning pass");
    anonymizer
}

/// A learned comment of several words is replaced in a configuration text, in any case and
/// glued to other tokens (todo 12).
///
/// # Panics
///
/// Panics when a spelling of the comment survives.
#[test]
fn a_multi_word_learned_value_is_replaced_in_a_configuration_text() {
    let mut anonymizer = learned_comment();
    let config = [
        "! $$$ Model: KN-1811",
        "ip route 0.0.0.0 0.0.0.0 GigabitEthernet0 auto !Planted Route Note",
        "ip route 0.0.0.0 0.0.0.0 GigabitEthernet1 auto !PLANTED route note",
        "ip route 0.0.0.0 0.0.0.0 GigabitEthernet2 auto x!Planted Route Note;y",
    ]
    .join("\n");
    let output = anonymizer.config(&config).unwrap_or_default();
    assert!(
        !fold(&output).contains(&fold(COMMENT)),
        "the comment survived the configuration anonymizer"
    );
    assert_eq!(
        output.matches("host-1").count(),
        3,
        "each spelling became the alias: {output}"
    );
    assert!(output.contains("x!host-1;y"), "adjacent tokens are kept");
}

/// A configuration text holding no learned value prints as the parser normalizes it
/// (todo 12).
///
/// # Panics
///
/// Panics when unrelated text changes.
#[test]
fn unrelated_configuration_text_is_unchanged() {
    let mut anonymizer = learned_comment();
    let config = [
        "! $$$ Model: KN-1811",
        "interface GigabitEthernet0",
        "    up",
        "!",
        "ip route 0.0.0.0 0.0.0.0 GigabitEthernet0 auto !Uplink route",
    ]
    .join("\n");
    assert_eq!(
        anonymizer.config(&config).ok(),
        config_text::normalize(&config).ok(),
        "only learned values change"
    );
}

/// The id and name of an interface reference in a hotspot row are kept and not learned; a
/// host name of the same shape beside it is aliased and learned (todo 12).
///
/// # Panics
///
/// Panics when the reference is aliased or the host name is not.
#[test]
fn an_interface_reference_keeps_its_id_and_name() {
    let mut anonymizer = fixed();
    let rows = json!({"host": [{
        "name": "Planted7",
        "interface": {"id": "Bridge0", "name": "Bridge0", "description": "Planted Segment"},
    }, {
        "interface": {"name": "Planted8"},
    }]});
    let output = anonymizer.json(&rows).unwrap_or_default();
    let field = |pointer: &str| output.pointer(pointer).and_then(Value::as_str);
    assert_eq!(field("/host/0/interface/id"), Some("Bridge0"), "id kept");
    assert_eq!(
        field("/host/0/interface/name"),
        Some("Bridge0"),
        "name kept"
    );
    for pointer in [
        "/host/0/name",
        "/host/0/interface/description",
        "/host/1/interface/name",
    ] {
        assert!(
            field(pointer).is_some_and(|alias| alias.starts_with("host-")),
            "{pointer} is aliased"
        );
    }
    let learned: Vec<String> = anonymizer
        .identifiers()
        .into_iter()
        .map(|identifier| identifier.value)
        .collect();
    assert!(
        !learned.iter().any(|value| value == "Bridge0"),
        "the interface id is not learned"
    );
    for planted in ["Planted7", "Planted8", "Planted Segment"] {
        assert!(
            learned.iter().any(|value| value == planted),
            "a planted name is not learned"
        );
    }
}
