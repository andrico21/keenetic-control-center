//! Namespace prefixes are derived from command paths, independently of risk lookup.

use alloc::collections::BTreeSet;
use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::{Catalog, HttpMethod, Risk};

/// Every virtual prefix contributes an ordinary leaf, including beside a Show leaf.
#[test]
fn empty_namespaces_are_ordinary_changes_at_every_catalog_depth() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        let commands = catalog
            .commands()
            .map(|command| command.path.as_str())
            .collect::<BTreeSet<_>>();
        let mut namespaces = BTreeSet::new();
        for path in &commands {
            let words = path.split_whitespace().collect::<Vec<_>>();
            for depth in 1..words.len() {
                let prefix = words
                    .iter()
                    .take(depth)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                if !commands.contains(prefix.as_str()) {
                    let _: bool = namespaces.insert(prefix);
                }
            }
        }
        assert!(!namespaces.is_empty(), "catalog has virtual prefixes");
        for path in namespaces {
            let body = path
                .split_whitespace()
                .rev()
                .fold(json!({}), |child, word| json!({word:child}));
            let mut mixed = body.clone();
            // Use a whole-path Show sibling so even an empty `show` subtree remains present.
            drop(
                mixed
                    .as_object_mut()
                    .ok_or("root object")?
                    .insert("show version".to_owned(), json!({})),
            );
            for input in [body, mixed] {
                let request = catalog
                    .validate("", HttpMethod::Post, &input)
                    .map_err(|issues| format!("{version} {path}: {issues:?}"))?;
                assert!(request.risk >= Risk::Write, "{version} {path}: {input}");
                assert_eq!(request.ordinary_paths, [path.as_str()], "{version} {input}");
                assert!(
                    request.persisted_paths.is_empty(),
                    "namespace is not persisted"
                );
                assert!(
                    !request.persists_immediately,
                    "namespace needs explicit save"
                );
            }
        }
    }
    Ok(())
}

/// Empty root and the catalogued Show command read; empty virtual prefixes fail closed.
#[test]
fn empty_show_namespaces_and_root_have_explicit_semantics() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        for (body, risk, ordinary) in [
            (json!({}), Risk::Read, Vec::<&str>::new()),
            (json!({"show":{}}), Risk::Read, Vec::new()),
            (
                json!({"show":{"clock":{}}}),
                Risk::Write,
                vec!["show clock"],
            ),
            (
                json!({"show":{"clock":{"date":{}}}}),
                Risk::Read,
                Vec::new(),
            ),
        ] {
            let request = catalog
                .validate("", HttpMethod::Post, &body)
                .map_err(|issues| format!("{version} {body}: {issues:?}"))?;
            assert_eq!(request.risk, risk, "{version} {body}");
            assert_eq!(request.ordinary_paths, ordinary, "{version} {body}");
        }
    }
    Ok(())
}

/// A Show leaf cannot supply the entire item's risk while its namespace sibling disappears.
#[test]
fn empty_namespace_siblings_cannot_take_the_read_route() -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
    let body = json!({"show":{"version":{}},"ip":{"http":{}}});
    let request = catalog
        .validate("", HttpMethod::Post, &body)
        .map_err(|issues| format!("{issues:?}"))?;
    assert_eq!(request.risk, Risk::Write);
    assert_eq!(request.ordinary_paths, ["ip http"]);
    Ok(())
}
