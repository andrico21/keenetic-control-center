//! Typed CLI matching against finite generated synopsis forms.

use alloc::{borrow::Cow, collections::BTreeMap};
use core::{cmp::Reverse, fmt};

use serde_json::{Map, Value};

pub(crate) use crate::cli_grammar::Synopsis;
use crate::{
    ArgumentKind, Catalog, Command, HttpMethod, Risk, ValidatedRequest, ValidationIssue,
    cli_grammar::{Form, command_forms},
    validate::boolean_keyword_forms,
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
    let pairs = align(form, tokens)?;
    let mut objects = BTreeMap::<&str, Map<String, Value>>::new();
    for ((path, node), token) in pairs {
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
                    .map_or_else(|_error| Value::String(token.to_owned()), Value::from),
                ArgumentKind::IpAddress
                | ArgumentKind::IpMask
                | ArgumentKind::IpAddressMask
                | ArgumentKind::MacAddress
                | ArgumentKind::ObjectName
                | ArgumentKind::Keyword
                | ArgumentKind::Password
                | ArgumentKind::String => Value::String(token.to_owned()),
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

/// Pairs form nodes with the words they spell.
///
/// Keywords must match exactly. A join `<a> [: <b>]` reads one `a:b` word, split at its
/// last colon, or the two words `a b`; the word count left for the rest of the form
/// decides which.
fn align<'form, 'syntax, 'token>(
    form: &'form Form<'syntax>,
    tokens: &[&'token str],
) -> Option<Vec<(&'form (&'syntax str, &'syntax Synopsis), &'token str)>> {
    let mut pairs = Vec::with_capacity(form.len());
    let mut nodes = form.iter();
    let mut words = tokens.iter();
    while let Some(node) = nodes.next() {
        let word = *words.next()?;
        match node.1 {
            Synopsis::Keyword(keyword) if keyword == word => pairs.push((node, word)),
            Synopsis::Argument(_) => match nodes.as_slice() {
                [
                    (_, Synopsis::Keyword(colon)),
                    (_, Synopsis::Argument(_)),
                    ..,
                ] if colon == ":" => {
                    let joins = nodes
                        .as_slice()
                        .iter()
                        .filter(|(_, rest)| matches!(rest, Synopsis::Keyword(mark) if mark == ":"))
                        .count();
                    let separate =
                        words.as_slice().len() == nodes.as_slice().len().saturating_sub(joins);
                    let second = nodes.nth(1)?;
                    if separate {
                        pairs.extend([(node, word), (second, *words.next()?)]);
                    } else {
                        let (first_word, second_word) = word.rsplit_once(':')?;
                        pairs.extend([(node, first_word), (second, second_word)]);
                    }
                }
                _ => pairs.push((node, word)),
            },
            Synopsis::Keyword(_)
            | Synopsis::Sequence(_)
            | Synopsis::Optional(_)
            | Synopsis::Group(_)
            | Synopsis::Alternative(_) => return None,
        }
    }
    words.next().is_none().then_some(pairs)
}

/// Whether CLI words render a validated request of command `path` with leaf `body`.
///
/// The words must match one of the command's forms with valid values, and every
/// argument of the command must be given by both the line and `body`, or by neither,
/// with the same text. A `no` line renders a negated body, in one of the command's
/// negative forms or as `no` before a full positive form. Context arguments are checked
/// by type only: a leaf body does not carry them.
pub(crate) fn renders(
    catalog: &Catalog,
    synopses: &BTreeMap<String, Synopsis>,
    (path, value): (&str, &Value),
    tokens: &[&str],
) -> bool {
    let negative = tokens.first() == Some(&"no");
    let words = tokens.strip_prefix(&["no"]).unwrap_or(tokens);
    let (Some(command), Some(body)) = (catalog.lookup(path), value.as_object()) else {
        return false;
    };
    if negative != (body.get("no") == Some(&Value::Bool(true))) {
        return false;
    }
    let known = |key: &String| {
        key == "no"
            || command.arguments.contains_key(key)
            || command
                .arguments
                .values()
                .flat_map(boolean_keyword_forms)
                .any(|form| form == key)
    };
    if !body.keys().all(known) {
        return false;
    }
    let same = |bound: &Map<String, Value>| {
        command.arguments.iter().all(|(name, argument)| {
            text(bound.get(name))
                == text(body.get(name)).or_else(|| {
                    boolean_keyword_forms(argument)
                        .find(|form| body.get(*form) == Some(&Value::Bool(true)))
                        .map(Cow::Borrowed)
                })
        })
    };
    let polarities: &[bool] = if negative { &[true, false] } else { &[false] };
    polarities.iter().any(|polarity| {
        command_forms(synopses, path, *polarity).is_some_and(|forms| {
            forms.iter().any(
                |form| matches!(match_form(catalog, form, words), Some(Ok(bound)) if same(&bound)),
            )
        })
    })
}

/// The text of a scalar argument value, the form a CLI word carries; a string, possibly
/// a secret, is borrowed rather than copied.
fn text(value: Option<&Value>) -> Option<Cow<'_, str>> {
    match value? {
        Value::String(word) => Some(Cow::Borrowed(word.as_str())),
        Value::Number(number) => Some(Cow::Owned(number.to_string())),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// The catalog view a request was validated by, compared by firmware line and model view.
#[derive(Clone)]
pub(crate) struct Origin(Catalog);

impl Origin {
    /// The view `catalog` that validates a request.
    pub(crate) fn of(catalog: &Catalog) -> Self {
        Self(catalog.clone())
    }

    /// Whether CLI words render the request `(path, body)` in this view.
    pub(crate) fn renders(&self, request: (&str, &Value), words: &[&str]) -> bool {
        self.0.renders_cli(request, words)
    }
}

impl fmt::Debug for Origin {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Origin")
            .field("version", &self.0.version())
            .field("model_match", self.0.model_match())
            .finish()
    }
}

impl PartialEq for Origin {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.version() == other.0.version() && self.0.model_match() == other.0.model_match()
    }
}

/// Retains the raw escape only when no literal catalog prefix is known.
pub(crate) fn known_prefix(catalog: &Catalog, words: &[&str]) -> bool {
    catalog.commands().any(|command: &Command| {
        let prefix = command.path.split_whitespace().collect::<Vec<_>>();
        words.starts_with(&prefix)
    })
}
