//! Operator choices applied to a source before planning: settings left out and conflicting
//! scalars that take the source's value.

use alloc::collections::BTreeSet;

use kcc_config::config_text::{CliLine, Node, Token, flatten};
use kcc_migrate::source::SourceConfig;

/// Most indices in one choice list.
pub(crate) const MAX_CHOICES: usize = 4096;

/// The scalar keys of the source settings at `overwrite` (the words before the value).
pub(crate) fn overwrite_keys(
    source: &SourceConfig,
    overwrite: &BTreeSet<usize>,
) -> BTreeSet<String> {
    flatten(&source.ast)
        .iter()
        .enumerate()
        .filter(|(index, _line)| overwrite.contains(index))
        .filter_map(|(_index, line)| scalar_key(line))
        .collect()
}

/// A setting's words without its last one.
fn scalar_key(line: &CliLine) -> Option<String> {
    let words = line
        .tokens
        .iter()
        .flat_map(|token| match token {
            Token::Word(word) => vec![word.as_str()],
            Token::Ns3(payload) => vec!["ns3", payload.as_str()],
            _ => Vec::new(),
        })
        .collect::<Vec<_>>();
    words.split_last().map(|(_value, key)| key.join(" "))
}

/// `source` without the settings at `left_out` (and emptied contexts), with the
/// whole-source index of each kept setting.
pub(crate) fn without(
    source: &SourceConfig,
    left_out: &BTreeSet<usize>,
) -> (SourceConfig, Vec<usize>) {
    let mut kept = Vec::new();
    let mut next = 0_usize;
    let mut trimmed = source.clone();
    trim(&mut trimmed.ast.nodes, left_out, &mut next, &mut kept);
    (trimmed, kept)
}

/// Removes the leaves at `left_out` below `nodes`, counting leaves in order from `next`.
fn trim(
    nodes: &mut Vec<Node>,
    left_out: &BTreeSet<usize>,
    next: &mut usize,
    kept: &mut Vec<usize>,
) {
    nodes.retain_mut(|node| {
        if node.children.is_empty() {
            let index = *next;
            *next = next.saturating_add(1);
            let keep = !left_out.contains(&index);
            if keep {
                kept.push(index);
            }
            keep
        } else {
            trim(&mut node.children, left_out, next, kept);
            !node.children.is_empty()
        }
    });
}
