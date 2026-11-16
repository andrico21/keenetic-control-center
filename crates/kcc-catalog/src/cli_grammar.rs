//! Expansion of finite manual grammar and omitted parent contexts.

use alloc::collections::BTreeMap;
use core::{mem::take, slice};

use serde::Deserialize;

/// Ordered syntax retained from the generator.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "node", content = "value")]
pub(crate) enum Synopsis {
    /// Ordered words.
    Sequence(Vec<Self>),
    /// Optional words.
    Optional(Box<Self>),
    /// Grammar group or manual context boundary.
    Group(Box<Self>),
    /// Documented choices.
    Alternative(Vec<Self>),
    /// Named typed argument.
    Argument(String),
    /// Exact literal word.
    Keyword(String),
}

/// Flattened nodes retain the catalog path that owns each argument.
pub(crate) type Form<'syntax> = Vec<(&'syntax str, &'syntax Synopsis)>;

/// Reconstructs parents from the positive form, using the leaf's requested polarity.
pub(crate) fn command_forms<'syntax>(
    definitions: &'syntax BTreeMap<String, Synopsis>,
    path: &'syntax str,
    negative: bool,
) -> Option<Vec<Form<'syntax>>> {
    let synopsis = definitions.get(path)?;
    let forms = split_forms(synopsis, path);
    let positive = forms.first()?;
    let parent = parent_path(path, positive)?;
    let parents = if parent.is_empty() {
        vec![Vec::new()]
    } else {
        command_forms(definitions, parent, false)?
    };
    let mut expanded = Vec::new();
    for form in polarity_forms(&forms, negative)? {
        expanded.extend(expand_sequence(form)?);
    }
    if parents.len().saturating_mul(expanded.len()) > 4096 {
        return None;
    }
    Some(
        parents
            .iter()
            .flat_map(|parent_form| {
                expanded.iter().map(|form| {
                    parent_form
                        .iter()
                        .copied()
                        .chain(form.iter().map(|node| (path, *node)))
                        .collect()
                })
            })
            .collect(),
    )
}

/// The parent context path: `path` without the trailing words the form spells as its
/// own top-level keywords, in order and starting with the form's first word.
fn parent_path<'path>(path: &'path str, positive: &[&Synopsis]) -> Option<&'path str> {
    let keywords = positive
        .iter()
        .filter_map(|node| match node {
            Synopsis::Keyword(word) => Some(word.as_str()),
            Synopsis::Sequence(_)
            | Synopsis::Optional(_)
            | Synopsis::Group(_)
            | Synopsis::Alternative(_)
            | Synopsis::Argument(_) => None,
        })
        .collect::<Vec<_>>();
    let Some(Synopsis::Keyword(first)) = positive.first() else {
        return None;
    };
    let words = path.split(' ').collect::<Vec<_>>();
    let start = (0..words.len()).find(|start| {
        let suffix = words.get(*start..).unwrap_or_default();
        suffix.first() == Some(&first.as_str()) && {
            let mut spelled = keywords.iter();
            suffix
                .iter()
                .all(|word| spelled.any(|keyword| keyword == word))
        }
    })?;
    let parent = words.get(..start)?;
    Some(
        path.get(
            ..parent
                .iter()
                .map(|word| word.len().saturating_add(1))
                .sum::<usize>(),
        )?
        .trim_end(),
    )
}

/// The forms of one polarity. A manual lists one positive and one negative line, or
/// several positive lines followed by the same lines again for the `no` prefix.
fn polarity_forms<'forms, 'syntax>(
    forms: &'forms [Vec<&'syntax Synopsis>],
    negative: bool,
) -> Option<&'forms [Vec<&'syntax Synopsis>]> {
    match forms.len() {
        0..=2 => forms.get(usize::from(negative)).map(slice::from_ref),
        count => {
            let (positive, repeated) = forms.split_at_checked(count.checked_div(2)?)?;
            (count.is_multiple_of(2) && positive == repeated).then_some(positive)
        }
    }
}

/// Context markers separate a manual's synopsis lines; other groups are grammar. A
/// marker naming the command's first word (`(system)`, `(show)`, `(vpn-server)`) is
/// also the first word of its line.
fn split_forms<'syntax>(synopsis: &'syntax Synopsis, path: &str) -> Vec<Vec<&'syntax Synopsis>> {
    let nodes = match synopsis {
        Synopsis::Sequence(nodes) => nodes.as_slice(),
        Synopsis::Optional(_)
        | Synopsis::Group(_)
        | Synopsis::Alternative(_)
        | Synopsis::Argument(_)
        | Synopsis::Keyword(_) => slice::from_ref(synopsis),
    };
    let root = path.split(' ').next();
    let mut forms = Vec::new();
    let mut current = Vec::new();
    for node in nodes {
        if let Synopsis::Group(inner) = node
            && let Synopsis::Keyword(word) = inner.as_ref()
            && (word == "system"
                || Some(word.as_str()) == root
                || word == "config"
                || word.starts_with("config-"))
        {
            if !current.is_empty() {
                forms.push(take(&mut current));
            }
            if word == "system" || Some(word.as_str()) == root {
                current.push(inner.as_ref());
            }
        } else {
            current.push(node);
        }
    }
    if !current.is_empty() {
        forms.push(current);
    }
    forms
}

/// Expands only finite explicit grammar; repetitions remain unsupported literals.
fn expand(node: &Synopsis) -> Option<Vec<Vec<&Synopsis>>> {
    match node {
        Synopsis::Keyword(_) | Synopsis::Argument(_) => Some(vec![vec![node]]),
        Synopsis::Group(inner) => expand(inner),
        Synopsis::Optional(inner) => {
            let mut forms = expand(inner)?;
            forms.push(Vec::new());
            Some(forms)
        }
        Synopsis::Alternative(nodes) => {
            let mut forms = Vec::new();
            for child in nodes {
                forms.extend(expand(child)?);
            }
            (forms.len() <= 4096).then_some(forms)
        }
        Synopsis::Sequence(nodes) => expand_sequence(&nodes.iter().collect::<Vec<_>>()),
    }
}

/// Bounds the Cartesian product of optional and alternative forms.
fn expand_sequence<'syntax>(nodes: &[&'syntax Synopsis]) -> Option<Vec<Vec<&'syntax Synopsis>>> {
    let mut forms = vec![Vec::new()];
    for child in nodes {
        let alternatives = expand(child)?;
        if forms.len().saturating_mul(alternatives.len()) > 4096 {
            return None;
        }
        forms = forms
            .iter()
            .flat_map(|form| {
                alternatives
                    .iter()
                    .map(|alternative| form.iter().chain(alternative).copied().collect())
            })
            .collect();
    }
    Some(forms)
}
