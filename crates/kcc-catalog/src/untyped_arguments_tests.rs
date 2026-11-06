//! Generated-catalog invariant for synopsis arguments.

use alloc::collections::BTreeSet;
use core::error::Error;

use serde::{Deserialize, de::IgnoredAny};

use crate::generated;

#[derive(Deserialize)]
struct AllowlistedArgument {
    path: String,
    name: String,
}

#[derive(Deserialize)]
struct Shard {
    commands: Vec<GeneratedCommand>,
}

#[derive(Deserialize)]
struct GeneratedCommand {
    path: String,
    synopsis: Option<TestSynopsis>,
    arguments: serde_json::Map<String, serde_json::Value>,
}

struct UntypedAudit<'audit> {
    allowlist: &'audit BTreeSet<(String, String)>,
    seen_allowlisted: BTreeSet<(String, String)>,
    violations: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(tag = "node", content = "value")]
enum TestSynopsis {
    Sequence(Vec<Self>),
    Optional(Box<Self>),
    Group(Box<Self>),
    Alternative(Vec<Self>),
    Argument(String),
    Keyword(IgnoredAny),
}

#[test]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn every_synopsis_argument_is_typed_or_allowlisted() -> Result<(), Box<dyn Error>> {
    let allowlist: BTreeSet<(String, String)> = serde_json::from_str::<Vec<AllowlistedArgument>>(
        include_str!("../../../catalog/untyped-arguments.json"),
    )?
    .into_iter()
    .map(|entry| (entry.path, entry.name))
    .collect();
    let mut audit = UntypedAudit {
        allowlist: &allowlist,
        seen_allowlisted: BTreeSet::new(),
        violations: BTreeSet::new(),
    };
    for (relative_path, contents) in generated::FILES {
        if relative_path.ends_with("/index.json") {
            continue;
        }
        let version = relative_path
            .split('/')
            .nth(1)
            .ok_or("generated catalog path has no version")?;
        let shard: Shard = serde_json::from_str(contents)?;
        for command in shard.commands {
            if let Some(synopsis) = command.synopsis {
                audit.collect(&synopsis, &command.path, &command.arguments, version);
            }
        }
    }
    assert!(
        audit.violations.is_empty(),
        "synopsis arguments without generated types or allowlist entries: {:#?}",
        audit.violations
    );
    assert_eq!(
        audit.seen_allowlisted, allowlist,
        "the allowlist must equal the remaining untyped argument set"
    );
    Ok(())
}

impl UntypedAudit<'_> {
    fn collect(
        &mut self,
        synopsis: &TestSynopsis,
        path: &str,
        arguments: &serde_json::Map<String, serde_json::Value>,
        version: &str,
    ) {
        match synopsis {
            TestSynopsis::Sequence(nodes) | TestSynopsis::Alternative(nodes) => {
                for node in nodes {
                    self.collect(node, path, arguments, version);
                }
            }
            TestSynopsis::Optional(node) | TestSynopsis::Group(node) => {
                self.collect(node, path, arguments, version);
            }
            TestSynopsis::Argument(name) if !arguments.contains_key(name) => {
                let argument = (path.to_owned(), name.clone());
                if self.allowlist.contains(&argument) {
                    let _inserted = self.seen_allowlisted.insert(argument);
                } else {
                    let _inserted = self.violations.insert(format!("{version}:{path}::{name}"));
                }
            }
            TestSynopsis::Argument(_) | TestSynopsis::Keyword(_) => {}
        }
    }
}
