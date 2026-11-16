//! Committed corrections to the manuals' structural facts: untyped synopsis arguments,
//! synopsis errata, commands the manuals omit, and bare optional argument words.

use alloc::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use super::{
    Command, CommandKind, Grammar, UntypedArgument, ValueType, command_error, parse_arguments,
    parse_synopsis, read_text,
};
use crate::failure::GateError;

/// Every committed correction the parser applies.
#[derive(Debug, Default)]
pub(super) struct Corrections {
    /// Synopsis arguments intentionally left without a generated type.
    untyped: BTreeSet<UntypedArgument>,
    /// Synopsis errata and omitted commands, keyed by command path.
    errata: BTreeMap<String, Erratum>,
}

/// One entry of `catalog/synopsis-errata.json`. The `reason` member documents the entry
/// for reviewers and is not read here.
#[derive(Debug, Deserialize)]
struct Erratum {
    /// Full command path.
    path: String,
    /// Synopsis text in the manual's notation, replacing or supplying the manual's.
    synopsis: String,
    /// Argument types of a command the manuals omit; absent for a corrected synopsis.
    #[serde(default)]
    arguments: Option<BTreeMap<String, ValueType>>,
}

impl Corrections {
    /// Whether `argument` is intentionally left without a generated type.
    pub(super) fn is_untyped(&self, argument: &UntypedArgument) -> bool {
        self.untyped.contains(argument)
    }

    /// The corrected synopsis text of `path`, when an erratum replaces the manual's.
    pub(super) fn synopsis(&self, path: &str) -> Option<&str> {
        self.errata
            .get(path)
            .filter(|erratum| erratum.arguments.is_none())
            .map(|erratum| erratum.synopsis.as_str())
    }

    /// Adds every command the manuals omit, for all `models` of the version, and checks
    /// that each synopsis erratum still names a documented command.
    ///
    /// # Errors
    ///
    /// Returns a command error when an omitted command is documented after all, when an
    /// erratum names no documented command, or when an erratum synopsis does not parse.
    pub(super) fn complete(
        &self,
        union: &mut BTreeMap<String, Command>,
        version: &str,
        models: &BTreeSet<String>,
    ) -> Result<(), GateError> {
        for erratum in self.errata.values() {
            let documented = union.contains_key(&erratum.path);
            let Some(arguments) = &erratum.arguments else {
                if documented {
                    continue;
                }
                return Err(command_error(
                    "catalog build",
                    format!(
                        "synopsis erratum {} names no documented command",
                        erratum.path
                    ),
                ));
            };
            if documented {
                return Err(command_error(
                    "catalog build",
                    format!("omitted command {} is documented now", erratum.path),
                ));
            }
            let synopsis = parse_synopsis(&erratum.synopsis).ok_or_else(|| {
                command_error(
                    "catalog build",
                    format!("erratum synopsis of {} does not parse", erratum.path),
                )
            })?;
            drop(union.insert(
                erratum.path.clone(),
                Command {
                    path: erratum.path.clone(),
                    models: models.clone(),
                    since: version.to_owned(),
                    page: 0,
                    source_url: String::new(),
                    kind: CommandKind::Setting,
                    prefix_no: true,
                    multiple_input: false,
                    change_settings: true,
                    persists_immediately: false,
                    group_entry: false,
                    interface_type: None,
                    context: None,
                    synopsis: Some(synopsis),
                    arguments: arguments.clone(),
                    parse_warnings: Vec::new(),
                },
            ));
        }
        Ok(())
    }
}

/// Loads the untyped-argument allowlist and the synopsis errata.
///
/// # Errors
///
/// Returns an input or JSON parse error when a committed correction file is unavailable
/// or malformed.
pub(super) fn load(root: &Path) -> Result<Corrections, GateError> {
    Ok(Corrections {
        untyped: parse_json(root, "catalog/untyped-arguments.json")?,
        errata: parse_json::<Vec<Erratum>>(root, "catalog/synopsis-errata.json")?
            .into_iter()
            .map(|erratum| (erratum.path.clone(), erratum))
            .collect(),
    })
}

/// Reads one committed JSON correction file.
///
/// # Errors
///
/// Returns an input or JSON parse error.
fn parse_json<T>(root: &Path, relative: &str) -> Result<T, GateError>
where
    T: for<'de> Deserialize<'de>,
{
    let path = root.join(relative);
    serde_json::from_str(&read_text(&path)?).map_err(|source| {
        command_error(
            "catalog build",
            format!("cannot parse {}: {source}", path.display()),
        )
    })
}

/// Turns a bare optional word (`[ mac ]`) that names a typed row of the Arguments table
/// into that argument (`[ ‹mac› ]`). Keyword and Boolean rows stay literal words.
pub(super) fn promote_bare_arguments(
    grammar: Grammar,
    lines: &[&str],
) -> (Grammar, BTreeSet<String>) {
    let mut bare = BTreeSet::new();
    bare_optional_words(&grammar, &mut bare);
    let promoted = parse_arguments(lines, &bare)
        .into_iter()
        .filter(|(_, kind)| !matches!(kind, ValueType::Keyword(_) | ValueType::Boolean))
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    (promote(grammar, &promoted), promoted)
}

/// Collects the words that are the whole content of an optional node.
fn bare_optional_words(grammar: &Grammar, out: &mut BTreeSet<String>) {
    match grammar {
        Grammar::Optional(inner) => match inner.as_ref() {
            Grammar::Keyword(word) => {
                let _inserted = out.insert(word.clone());
            }
            other @ (Grammar::Sequence(_)
            | Grammar::Optional(_)
            | Grammar::Group(_)
            | Grammar::Alternative(_)
            | Grammar::Argument(_)) => bare_optional_words(other, out),
        },
        Grammar::Sequence(nodes) | Grammar::Alternative(nodes) => {
            for node in nodes {
                bare_optional_words(node, out);
            }
        }
        Grammar::Group(inner) => bare_optional_words(inner, out),
        Grammar::Argument(_) | Grammar::Keyword(_) => {}
    }
}

/// Rewrites `[ word ]` as `[ ‹word› ]` for every promoted word.
fn promote(grammar: Grammar, promoted: &BTreeSet<String>) -> Grammar {
    match grammar {
        Grammar::Optional(inner) => Grammar::Optional(Box::new(match *inner {
            Grammar::Keyword(word) if promoted.contains(&word) => Grammar::Argument(word),
            other @ (Grammar::Keyword(_)
            | Grammar::Sequence(_)
            | Grammar::Optional(_)
            | Grammar::Group(_)
            | Grammar::Alternative(_)
            | Grammar::Argument(_)) => promote(other, promoted),
        })),
        Grammar::Sequence(nodes) => Grammar::Sequence(
            nodes
                .into_iter()
                .map(|node| promote(node, promoted))
                .collect(),
        ),
        Grammar::Alternative(nodes) => Grammar::Alternative(
            nodes
                .into_iter()
                .map(|node| promote(node, promoted))
                .collect(),
        ),
        Grammar::Group(inner) => Grammar::Group(Box::new(promote(*inner, promoted))),
        leaf @ (Grammar::Argument(_) | Grammar::Keyword(_)) => leaf,
    }
}
