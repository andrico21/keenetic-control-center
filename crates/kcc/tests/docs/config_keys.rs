//! `docs/CONFIG.md` documents exactly the keys `kcc.toml` accepts.
//!
//! The accepted keys come from the real `Config` deserializer: every table rejects
//! unknown keys, and the rejection names the fields the table has.

use alloc::collections::{BTreeMap, BTreeSet};
use core::error::Error;
use std::{fs, path::Path};

use kcc_app::settings::Config;
use tempfile::TempDir;

use super::markdown::{first_code_span, root};

/// The unknown key every probe sends.
const PROBE: &str = "kcc_doc_probe";

/// One table of `kcc.toml`: its id in `CONFIG.md` and the TOML that opens it.
struct Table {
    /// `section.sub` path, with `#<kind>` for a tagged sink variant; empty for the root.
    id: &'static str,
    /// TOML text opening the table, or `None` when the table has no keys to probe.
    opening: Option<&'static str>,
}

/// Every table of `kcc.toml`.
const TABLES: &[Table] = &[
    Table {
        id: "",
        opening: Some(""),
    },
    Table {
        id: "server",
        opening: Some("[server]\n"),
    },
    Table {
        id: "server.log_context",
        opening: Some("[server.log_context]\n"),
    },
    Table {
        id: "server.security_headers",
        opening: Some("[server.security_headers]\n"),
    },
    Table {
        id: "server.auth",
        opening: Some("[server.auth]\n"),
    },
    Table {
        id: "observability",
        opening: Some("[observability]\n"),
    },
    Table {
        id: "web",
        opening: Some("[web]\n"),
    },
    Table {
        id: "mcp",
        opening: Some("[mcp]\n"),
    },
    Table {
        id: "outbound",
        opening: Some("[outbound]\n"),
    },
    Table {
        id: "state",
        opening: Some("[state]\n"),
    },
    Table {
        id: "backups",
        opening: Some("[backups]\n"),
    },
    Table {
        id: "audit",
        opening: Some("[audit]\n"),
    },
    Table {
        id: "cli",
        opening: Some("[cli]\n"),
    },
    Table {
        id: "privacy",
        opening: Some("[privacy]\n"),
    },
    Table {
        id: "metrics",
        opening: Some("[metrics]\n"),
    },
    Table {
        id: "logs",
        opening: Some("[logs]\n"),
    },
    Table {
        id: "logs.sinks#loki",
        opening: Some("[[logs.sinks]]\nkind = \"loki\"\n"),
    },
    Table {
        id: "logs.sinks#elasticsearch",
        opening: Some("[[logs.sinks]]\nkind = \"elasticsearch\"\n"),
    },
    // `stdout` has no fields, and serde accepts unknown keys in a unit variant, so it
    // cannot be probed; its documented table must stay empty.
    Table {
        id: "logs.sinks#stdout",
        opening: None,
    },
    Table {
        id: "notify",
        opening: Some("[notify]\n"),
    },
    Table {
        id: "notify.telegram",
        opening: Some("[notify.telegram]\n"),
    },
    Table {
        id: "routers",
        opening: Some("[[routers]]\n"),
    },
];

/// The field names the deserializer reports for one table.
fn schema_keys(opening: &str) -> Result<BTreeSet<String>, String> {
    let text = format!("{opening}{PROBE} = 1\n");
    let Err(error) = Config::from_toml_str(&text) else {
        return Err(format!("the probe was accepted: {text:?}"));
    };
    let message = error.to_string();
    let Some((_, expected)) = message.split_once("expected") else {
        return Err(format!("no field list in {message:?}"));
    };
    Ok(expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect())
}

/// The keys documented per table id in the Markdown `text`.
fn documented_keys(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut tables: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        match (line.strip_prefix('#'), &current) {
            (Some(marks), _) => {
                current = table_id(marks.trim_start_matches('#').trim());
                if let Some(id) = &current {
                    let _: &mut BTreeSet<String> = tables.entry(id.clone()).or_default();
                }
            }
            (None, Some(id)) => {
                let key = line
                    .strip_prefix("| `")
                    .and_then(|row| row.split_once('`'))
                    .map(|(name, _)| name.to_owned());
                if let Some(name) = key {
                    let _: bool = tables.entry(id.clone()).or_default().insert(name);
                }
            }
            (None, None) => {}
        }
    }
    tables
}

/// The table id a heading names, if it names one.
fn table_id(heading: &str) -> Option<String> {
    if heading == "Top level" {
        return Some(String::new());
    }
    let span = first_code_span(heading)?;
    let path = span.strip_prefix('[')?.trim_matches(['[', ']']);
    let kind = heading
        .split_once("kind = \"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(kind, _)| kind);
    Some(kind.map_or_else(|| path.to_owned(), |variant| format!("{path}#{variant}")))
}

/// Checks that the configuration reference at `path` documents exactly the schema keys.
pub(crate) fn check(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let documented = documented_keys(&text);
    let mut problems = Vec::new();
    for table in TABLES {
        let schema = match table.opening {
            Some(opening) => schema_keys(opening)?,
            None => BTreeSet::new(),
        };
        let Some(listed) = documented.get(table.id) else {
            problems.push(format!("table `{}` has no section", table.id));
            continue;
        };
        for key in schema.difference(listed) {
            problems.push(format!("`{}` key `{key}` is not documented", table.id));
        }
        for key in listed.difference(&schema) {
            problems.push(format!("`{}` documents unknown key `{key}`", table.id));
        }
    }
    for id in documented.keys() {
        if !TABLES.iter().any(|table| table.id == id) {
            problems.push(format!("section `{id}` is not a kcc.toml table"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

#[test]
fn config_reference_lists_every_key_of_the_schema() -> Result<(), String> {
    check(&root().join("docs/CONFIG.md"))
}

#[test]
fn config_reference_check_fails_when_a_key_is_missing() -> Result<(), Box<dyn Error>> {
    let original = fs::read_to_string(root().join("docs/CONFIG.md"))?;
    let removed = "| `queue_max` |";
    assert!(original.contains(removed), "the mutation target moved");
    let mutated = original
        .lines()
        .filter(|line| !line.starts_with(removed))
        .collect::<Vec<_>>()
        .join("\n");
    let directory = TempDir::new()?;
    let copy = directory.path().join("CONFIG.md");
    fs::write(&copy, mutated)?;
    let Err(message) = check(&copy) else {
        return Err("the check passed without `queue_max`".into());
    };
    assert!(
        message.contains("`logs` key `queue_max` is not documented"),
        "{message}"
    );
    Ok(())
}
