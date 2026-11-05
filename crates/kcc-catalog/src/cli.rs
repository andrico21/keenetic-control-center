//! Conservative CLI conversion using ordered generated synopsis facts.

use core::{mem::take, slice};

use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Map, Value};

use crate::{ArgumentKind, Command, ValidationIssue};

/// Ordered grammar emitted by the catalog generator, retained without flattening alternatives.
#[derive(Debug, Deserialize)]
#[serde(tag = "node", content = "value")]
pub(crate) enum Synopsis {
    /// Ordered nodes.
    Sequence(Vec<Self>),
    /// Optional input, not supported by the fixed-form parser.
    Optional(IgnoredAny),
    /// Parenthesized context or grammar group.
    Group(Box<Self>),
    /// Alternative forms, not supported by the fixed-form parser.
    Alternative(IgnoredAny),
    /// Named positional argument.
    Argument(String),
    /// Literal CLI word.
    Keyword(String),
}

/// Converts a fixed manual form to the object consumed by the ordinary value validator.
///
/// # Errors
///
/// Returns syntax issues when the line cannot be mapped confidently; scalar type errors
/// are checked by the caller through the ordinary JSON request validator.
pub(crate) fn cli_value(
    command: &Command,
    synopsis: Option<&Synopsis>,
    tokens: &[&str],
) -> Result<Value, Vec<ValidationIssue>> {
    let negative = tokens.first() == Some(&"no");
    if negative && !command.prefix_no {
        return Err(vec![ValidationIssue::NoPrefixUnsupported]);
    }
    let unsupported = || {
        vec![ValidationIssue::UnsupportedCliSyntax {
            path: command.path.clone(),
        }]
    };
    let forms = synopsis.and_then(fixed_forms).ok_or_else(unsupported)?;
    let form = forms.get(usize::from(negative)).ok_or_else(unsupported)?;
    let mut nodes = form.iter();
    for word in command.path.split_whitespace() {
        if !matches!(nodes.next(), Some(Synopsis::Keyword(keyword)) if keyword == word) {
            return Err(unsupported());
        }
    }
    let mut arguments = Vec::new();
    for node in nodes {
        if negative {
            return Err(unsupported());
        }
        let Synopsis::Argument(name) = node else {
            return Err(unsupported());
        };
        let argument = command.arguments.get(name).ok_or_else(unsupported)?;
        if arguments.contains(&argument) {
            return Err(unsupported());
        }
        arguments.push(argument);
    }
    let values = tokens.iter().skip(
        command
            .path
            .split_whitespace()
            .count()
            .saturating_add(usize::from(negative)),
    );
    if values.len() != arguments.len() {
        return Err(vec![ValidationIssue::InvalidCliSyntax]);
    }
    let mut object = Map::new();
    for (argument, token) in arguments.into_iter().zip(values) {
        let value = match argument.kind {
            ArgumentKind::Integer => token
                .parse::<i64>()
                .map_or_else(|_error| Value::String((*token).to_owned()), Value::from),
            ArgumentKind::IpAddress
            | ArgumentKind::IpMask
            | ArgumentKind::MacAddress
            | ArgumentKind::ObjectName
            | ArgumentKind::Keyword
            | ArgumentKind::String => Value::String((*token).to_owned()),
        };
        drop(object.insert(argument.name.clone(), value));
    }
    if negative {
        drop(object.insert("no".to_owned(), Value::Bool(true)));
    }
    Ok(Value::Object(object))
}

/// Retains fixed positive/negative forms separated by the generator's context groups.
///
/// The generator joins synopsis lines and strips `no`; only a repeated, identical
/// context with two fixed forms can recover that boundary. Other grammar is rejected.
fn fixed_forms(synopsis: &Synopsis) -> Option<Vec<Vec<&Synopsis>>> {
    let nodes = match synopsis {
        Synopsis::Sequence(nodes) => nodes.as_slice(),
        Synopsis::Keyword(_)
        | Synopsis::Argument(_)
        | Synopsis::Group(_)
        | Synopsis::Optional(_)
        | Synopsis::Alternative(_) => slice::from_ref(synopsis),
    };
    let mut forms = Vec::new();
    let mut current = Vec::new();
    let mut context = None;
    for node in nodes {
        match node {
            Synopsis::Group(inner) => {
                let Synopsis::Keyword(word) = inner.as_ref() else {
                    return None;
                };
                if context.is_some_and(|previous| previous != word) {
                    return None;
                }
                context = Some(word);
                if !current.is_empty() {
                    forms.push(take(&mut current));
                }
                if word != "config" {
                    current.push(inner.as_ref());
                }
            }
            Synopsis::Keyword(_)
            | Synopsis::Argument(_)
            | Synopsis::Optional(_)
            | Synopsis::Alternative(_) => current.push(node),
            Synopsis::Sequence(_) => return None,
        }
    }
    if !current.is_empty() {
        forms.push(current);
    }
    (forms.len() <= 2).then_some(forms)
}
