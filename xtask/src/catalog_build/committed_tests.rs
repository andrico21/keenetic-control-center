//! Hermetic guards over the committed `catalog/<version>/*.json` shards.
//!
//! They need no `catalog/.cache`: the cache-backed tests in `tests.rs` protect the parser,
//! these protect the generated data every build ships.

use core::error::Error;
use std::{fs, path::Path};

use serde_json::Value;

use super::expected::{keyword_problems, spot_problems, typing_problems};

/// Committed catalog versions.
const VERSIONS: [&str; 3] = ["4.3", "5.0", "5.1"];
/// Versions whose manuals document every keyword literal in `KEYWORD_LITERALS`
/// (`user tag manager` appears in 5.0).
const KEYWORD_VERSIONS: [&str; 2] = ["5.0", "5.1"];
/// Copyright boundary: no stored string may carry more than this many words.
const MAX_WORDS: usize = 12;

/// Returns the repository root.
fn root() -> Result<&'static Path, Box<dyn Error>> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask manifest has no parent")?)
}

/// Loads every committed command of one version.
fn commands(version: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut commands = Vec::new();
    for entry in fs::read_dir(root()?.join("catalog").join(version))? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json")
            || path.file_name().is_some_and(|name| name == "index.json")
        {
            continue;
        }
        let shard: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        let Some(Value::Array(shard_commands)) = shard.get("commands").cloned() else {
            return Err(format!("{} has no commands array", path.display()).into());
        };
        commands.extend(shard_commands);
    }
    if commands.is_empty() {
        return Err(format!("catalog {version} has no committed commands").into());
    }
    Ok(commands)
}

/// Collects every string value nested in `value`.
fn strings<'value>(value: &'value Value, out: &mut Vec<&'value str>) {
    match value {
        Value::String(text) => out.push(text),
        Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
        Value::Object(map) => map.values().for_each(|item| strings(item, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[test]
fn committed_keyword_arguments_retain_documented_literals() -> Result<(), Box<dyn Error>> {
    for version in KEYWORD_VERSIONS {
        let problems = keyword_problems(&commands(version)?);
        assert!(problems.is_empty(), "catalog {version}: {problems:#?}");
    }
    Ok(())
}

#[test]
fn committed_ambiguous_arguments_use_semantic_types() -> Result<(), Box<dyn Error>> {
    for version in VERSIONS {
        let problems = typing_problems(&commands(version)?);
        assert!(problems.is_empty(), "catalog {version}: {problems:#?}");
    }
    Ok(())
}

#[test]
fn committed_spot_checks_hold() -> Result<(), Box<dyn Error>> {
    for version in VERSIONS {
        let problems = spot_problems(&commands(version)?);
        assert!(problems.is_empty(), "catalog {version}: {problems:#?}");
    }
    Ok(())
}

#[test]
fn committed_index_meets_the_synopsis_gate() -> Result<(), Box<dyn Error>> {
    for version in VERSIONS {
        let path = root()?.join("catalog").join(version).join("index.json");
        let index: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        let count = |name: &str| index.get(name).and_then(Value::as_u64).unwrap_or(0);
        let (leaves, synopses) = (count("reference_leaf_count"), count("synopsis_count"));
        assert!(leaves > 0, "catalog {version}: no reference leaves");
        assert!(
            synopses.saturating_mul(100) >= leaves.saturating_mul(98),
            "catalog {version}: 98% synopsis gate ({synopses}/{leaves})"
        );
    }
    Ok(())
}

#[test]
fn committed_strings_stay_under_the_copyright_cap() -> Result<(), Box<dyn Error>> {
    for version in VERSIONS {
        let commands = Value::Array(commands(version)?);
        let mut texts = Vec::new();
        strings(&commands, &mut texts);
        let long: Vec<&str> = texts
            .into_iter()
            .filter(|text| text.split_whitespace().count() > MAX_WORDS)
            .collect();
        assert!(
            long.is_empty(),
            "catalog {version}: prose-length strings {long:#?}"
        );
    }
    Ok(())
}
