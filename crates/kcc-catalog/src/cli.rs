//! Typed CLI matching against finite generated synopsis forms.

use alloc::collections::BTreeMap;
use core::cmp::Reverse;

use serde_json::{Map, Value};

pub(crate) use crate::cli_grammar::Synopsis;
use crate::{
    ArgumentKind, Catalog, Command, HttpMethod, Risk, ValidatedRequest, ValidationIssue,
    cli_grammar::{Form, command_forms},
};

/// Resolves context instances and validates all arguments before capturing the leaf request.
///
/// # Errors
/// Returns value-free syntax or scalar issues; known paths never become raw requests.
pub(crate) fn validate(
    catalog: &Catalog,
    synopses: &BTreeMap<String, Synopsis>,
    tokens: &[&str],
) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
    let negative = tokens.first() == Some(&"no");
    let words = tokens.strip_prefix(&["no"]).unwrap_or(tokens);
    let mut candidates = catalog
        .commands()
        .filter(|command| {
            let mut actual = words.iter();
            command
                .path
                .split_whitespace()
                .all(|word| actual.by_ref().any(|token| *token == word))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|command| Reverse(command.path.split_whitespace().count()));
    let mut issue = vec![ValidationIssue::InvalidCliSyntax];
    for command in candidates {
        if negative && !command.prefix_no {
            return Err(vec![ValidationIssue::NoPrefixUnsupported]);
        }
        let Some(forms) = command_forms(synopses, &command.path, negative) else {
            issue = vec![ValidationIssue::UnsupportedCliSyntax {
                path: command.path.clone(),
            }];
            continue;
        };
        let variable_destructive =
            catalog.risk(&command.path) == Some(Risk::Destructive) && forms.len() > 1;
        let mut matched = false;
        for form in &forms {
            if let Some(result) = match_form(catalog, form, words) {
                matched = true;
                match result {
                    Ok(mut value) => {
                        if variable_destructive {
                            return Err(vec![ValidationIssue::UnsupportedCliSyntax {
                                path: command.path.clone(),
                            }]);
                        }
                        if negative {
                            drop(value.insert("no".to_owned(), Value::Bool(true)));
                        }
                        return catalog.validate(
                            &command.path,
                            HttpMethod::Post,
                            &Value::Object(value),
                        );
                    }
                    Err(issues) => issue = issues,
                }
            }
        }
        if matched {
            return Err(issue);
        }
    }
    Err(issue)
}

/// Matches exact syntax first, then checks each context's scalar object independently.
fn match_form(
    catalog: &Catalog,
    form: &Form<'_>,
    tokens: &[&str],
) -> Option<Result<Map<String, Value>, Vec<ValidationIssue>>> {
    if form.len() != tokens.len()
        || !form
            .iter()
            .zip(tokens)
            .all(|((_, node), token)| match node {
                Synopsis::Keyword(word) => word == token,
                Synopsis::Argument(_) => true,
                Synopsis::Sequence(_)
                | Synopsis::Optional(_)
                | Synopsis::Group(_)
                | Synopsis::Alternative(_) => false,
            })
    {
        return None;
    }
    let mut objects = BTreeMap::<&str, Map<String, Value>>::new();
    for ((path, node), token) in form.iter().zip(tokens) {
        let command = catalog.lookup(path)?;
        let object = objects.entry(path).or_default();
        let matched_argument = match node {
            Synopsis::Argument(name) => Some(command.arguments.get(name)?),
            Synopsis::Keyword(word) => command.arguments.values().find(|argument| {
                argument.kind == ArgumentKind::Keyword && argument.values.contains(word)
            }),
            Synopsis::Sequence(_)
            | Synopsis::Optional(_)
            | Synopsis::Group(_)
            | Synopsis::Alternative(_) => return None,
        };
        if let Some(argument) = matched_argument {
            let value = match argument.kind {
                ArgumentKind::Integer => token
                    .parse::<i64>()
                    .map_or_else(|_error| Value::String((*token).to_owned()), Value::from),
                ArgumentKind::IpAddress
                | ArgumentKind::IpMask
                | ArgumentKind::IpAddressMask
                | ArgumentKind::MacAddress
                | ArgumentKind::ObjectName
                | ArgumentKind::Keyword
                | ArgumentKind::Password
                | ArgumentKind::String => Value::String((*token).to_owned()),
            };
            if object.insert(argument.name.clone(), value).is_some() {
                return Some(Err(vec![ValidationIssue::UnsupportedCliSyntax {
                    path: command.path.clone(),
                }]));
            }
        }
    }
    for (path, object) in &objects {
        if let Err(issues) =
            catalog.validate(path, HttpMethod::Post, &Value::Object(object.clone()))
        {
            return Some(Err(issues));
        }
    }
    let (leaf, _) = form.last()?;
    Some(Ok(objects.remove(leaf)?))
}

/// Retains the raw escape only when no literal catalog prefix is known.
pub(crate) fn known_prefix(catalog: &Catalog, words: &[&str]) -> bool {
    catalog.commands().any(|command: &Command| {
        let prefix = command.path.split_whitespace().collect::<Vec<_>>();
        words.starts_with(&prefix)
    })
}
