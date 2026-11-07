//! Expansion of finite manual grammar and omitted parent contexts.

use alloc::collections::BTreeMap;
use core::{mem::take, slice};

use serde::Deserialize;

/// Ordered syntax retained from the generator.
#[derive(Debug, Deserialize)]
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
    let forms = split_forms(synopsis)?;
    let positive = forms.first()?;
    let leading = positive
        .iter()
        .map_while(|node| match node {
            Synopsis::Keyword(word) => Some(word.as_str()),
            Synopsis::Sequence(_)
            | Synopsis::Optional(_)
            | Synopsis::Group(_)
            | Synopsis::Alternative(_)
            | Synopsis::Argument(_) => None,
        })
        .collect::<Vec<_>>();
    let parent = (1..=leading.len()).rev().find_map(|length| {
        path.strip_suffix(&leading.get(..length)?.join(" "))
            .filter(|prefix| prefix.is_empty() || prefix.ends_with(' '))
            .map(str::trim_end)
    })?;
    let parents = if parent.is_empty() {
        vec![Vec::new()]
    } else {
        command_forms(definitions, parent, false)?
    };
    let expanded = expand_sequence(forms.get(usize::from(negative))?)?;
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

/// Context markers separate positive and negative manual lines; other groups are grammar.
fn split_forms(synopsis: &Synopsis) -> Option<Vec<Vec<&Synopsis>>> {
    let nodes = match synopsis {
        Synopsis::Sequence(nodes) => nodes.as_slice(),
        Synopsis::Optional(_)
        | Synopsis::Group(_)
        | Synopsis::Alternative(_)
        | Synopsis::Argument(_)
        | Synopsis::Keyword(_) => slice::from_ref(synopsis),
    };
    let mut forms = Vec::new();
    let mut current = Vec::new();
    for node in nodes {
        if let Synopsis::Group(inner) = node
            && let Synopsis::Keyword(word) = inner.as_ref()
            && (word == "system" || word == "config" || word.starts_with("config-"))
        {
            if !current.is_empty() {
                forms.push(take(&mut current));
            }
            if word == "system" {
                current.push(inner.as_ref());
            }
        } else {
            current.push(node);
        }
    }
    if !current.is_empty() {
        forms.push(current);
    }
    (forms.len() <= 2).then_some(forms)
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
