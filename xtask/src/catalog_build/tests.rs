//! Catalog parser tests.
//!
//! Unit tests use inline facts-only fixtures. The maintainer tests over the extracted
//! KN-1811 5.1 manual in `catalog/.cache` are `#[ignore]`d: the cache is gitignored and
//! fetched from the network (see `catalog/README.md`).

use alloc::collections::BTreeSet;
use core::error::Error;
use std::{fs, path::Path};

use serde_json::Value;

use super::{
    ModelCatalog, ValueType, argument_names, expected, load_untyped_allowlist, parse_arguments,
    parse_model, parse_synopsis, parse_value_type,
};
use crate::catalog::{Lock, lock_path};

/// Why the cache-backed tests are ignored by default.
const NEEDS_CACHE: &str = "needs catalog/.cache (cargo xtask catalog fetch && extract)";

#[test]
fn synopsis_parser_recognizes_arguments_and_nested_grammar() {
    let text = "ip static [ \u{2039}protocol\u{203a} ] ( \u{2039}interface\u{203a} | ( \u{2039}address\u{203a} \u{2039}mask\u{203a} ) )";
    let names = argument_names(text);
    assert_eq!(
        names,
        BTreeSet::from([
            "address".to_owned(),
            "interface".to_owned(),
            "mask".to_owned(),
            "protocol".to_owned(),
        ]),
        "argument markers"
    );
    assert!(parse_synopsis(text).is_some(), "nested grammar parses");
}

#[test]
fn truncated_synopsis_is_a_warning() {
    let grammar = parse_synopsis("ip route [ \u{2039}address\u{203a}");
    assert!(grammar.is_none(), "unclosed optional is rejected");
}

#[test]
fn ambiguous_value_cells_map_to_semantic_types() {
    let cases = [
        ("gateway", "Prefix", "IpAddress"),
        ("network", "Prefix", "IpAddress"),
        ("mask", "Prefix", "IpMask"),
        ("prefix", "Prefix", "IpAddressMask"),
        ("interface", "Prefix", "Interface"),
        ("schedule", "Schedule", "ObjectName"),
        ("policy", "Policy", "ObjectName"),
        ("password", "String", "Password"),
        ("fqdn", "FQDN", "String"),
    ];
    for (name, cell, tag) in cases {
        let actual = serde_json::to_value(parse_value_type(name, cell)).ok();
        assert_eq!(
            actual
                .as_ref()
                .and_then(|value| value.get("type")?.as_str()),
            Some(tag),
            "{name} {cell}"
        );
    }
}

#[test]
fn value_column_continuation_rows_extend_keywords() {
    let lines = [
        "Arguments               Argument       Value          Description",
        "                        mode           alpha          x",
        "                                       beta           x",
        "                                                      x",
        "                        schedule       Schedule       x",
        "                        gateway        Prefix         x",
    ];
    let names = ["gateway", "mode", "schedule"].map(str::to_owned).into();
    let parsed = parse_arguments(&lines, &names);
    assert!(
        matches!(parsed.get("mode"), Some(ValueType::Keyword(values)) if values == &BTreeSet::from(["alpha".to_owned(), "beta".to_owned()])),
        "continuation literal joins the keyword set: {parsed:?}"
    );
    assert!(
        matches!(parsed.get("schedule"), Some(ValueType::ObjectName)),
        "schedule"
    );
    assert!(
        matches!(parsed.get("gateway"), Some(ValueType::IpAddress)),
        "gateway"
    );
}

/// Parses the cached KN-1811 5.1 manual and returns it with its commands as JSON.
fn parse_kn_1811() -> Result<(&'static Path, ModelCatalog, Vec<Value>), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask manifest has no parent")?;
    let lock = Lock::load(&lock_path(root))?;
    let entry = lock
        .entries
        .iter()
        .find(|entry| entry.version == "5.1" && entry.model == "KN-1811")
        .ok_or("missing KN-1811 5.1 lock entry")?;
    let parsed = parse_model(root, entry, &load_untyped_allowlist(root)?)?;
    let Value::Array(commands) = serde_json::to_value(&parsed.commands)? else {
        return Err("commands do not serialize to an array".into());
    };
    Ok((root, parsed, commands))
}

#[test]
#[ignore = "needs catalog/.cache (cargo xtask catalog fetch && extract)"]
fn kn_1811_spot_checks_and_copyright_boundary() -> Result<(), Box<dyn Error>> {
    let (root, parsed, commands) =
        parse_kn_1811().map_err(|error| format!("{NEEDS_CACHE}: {error}"))?;
    assert!(
        parsed.synopsis_count.saturating_mul(100) >= parsed.leaf_count.saturating_mul(98),
        "98% synopsis gate"
    );
    let problems = expected::spot_problems(&commands);
    assert!(problems.is_empty(), "{problems:#?}");

    let source = fs::read_to_string(root.join("catalog/.cache/5.1/kn-1811.txt"))?;
    let source_words: Vec<&str> = source.split_whitespace().collect();
    let serialized = serde_json::to_string(&parsed.commands)?;
    let stored_words: BTreeSet<&str> = serialized.split_whitespace().collect();
    assert!(
        !source_words
            .windows(13)
            .any(|window| window.iter().all(|word| stored_words.contains(word))),
        "stored fields do not reproduce 13 consecutive source words"
    );
    Ok(())
}

#[test]
#[ignore = "needs catalog/.cache (cargo xtask catalog fetch && extract)"]
fn ambiguous_argument_rows_use_semantic_types() -> Result<(), Box<dyn Error>> {
    let (_, _, commands) = parse_kn_1811().map_err(|error| format!("{NEEDS_CACHE}: {error}"))?;
    let problems = expected::typing_problems(&commands);
    assert!(problems.is_empty(), "{problems:#?}");
    Ok(())
}

#[test]
#[ignore = "needs catalog/.cache (cargo xtask catalog fetch && extract)"]
fn value_column_keywords_retain_documented_literals() -> Result<(), Box<dyn Error>> {
    let (_, _, commands) = parse_kn_1811().map_err(|error| format!("{NEEDS_CACHE}: {error}"))?;
    let problems = expected::keyword_problems(&commands);
    assert!(problems.is_empty(), "{problems:#?}");
    Ok(())
}
