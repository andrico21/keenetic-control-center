//! Simulated `access-list <name> rule <index> ...` commands (CLI manual 3.3.4): one line
//! per rule property, and `order`, which moves a rule instead of being stored.
//!
//! A real router keeps a rule's properties with the rule when it moves; the simulator
//! renumbers the property lines the same way. Assumed from the R-CLI documentation, not
//! verified on a router.

use kcc_config::config_text::{Ast, Node, Token};

use super::tokens::{node_from_tokens, words};

/// The rule properties one line sets and the `no` form clears.
const PROPERTIES: [&str; 3] = ["disable", "description", "schedule"];

/// Applies an access-list rule command; `false` leaves any other line to the leaf table.
pub(super) fn apply(ast: &mut Ast, command: &[String], negated: bool) -> bool {
    let [access_list, name, rule, index, keyword, values @ ..] = command else {
        return false;
    };
    if access_list != "access-list" || rule != "rule" {
        return false;
    }
    let Ok(position) = index.parse::<usize>() else {
        return false;
    };
    let context = [access_list.as_str(), name.as_str()];
    let Some(list) = ast
        .nodes
        .iter_mut()
        .find(|node| words(&node.tokens) == context)
    else {
        return true;
    };
    match (keyword.as_str(), values, negated) {
        ("order", [target], false) => {
            if let Ok(destination) = target.parse::<usize>() {
                reorder(list, position, destination);
            }
            true
        }
        (property, _, _) if PROPERTIES.contains(&property) => {
            list.children
                .retain(|child| !is_property(child, index, property));
            if !negated {
                let tokens: Vec<Token> = [rule, index, keyword]
                    .into_iter()
                    .chain(values)
                    .map(|word| Token::Word(word.clone()))
                    .collect();
                if let Some(node) = node_from_tokens(&tokens) {
                    list.children.push(node);
                }
            }
            true
        }
        _ => false,
    }
}

/// Moves rule `from` so that it becomes rule `to`; out-of-range positions change nothing.
fn reorder(list: &mut Node, from: usize, to: usize) {
    let rules = rule_positions(list);
    let (Some(&source), true) = (rules.get(from), to < rules.len()) else {
        return;
    };
    let moved = list.children.remove(source);
    let remaining = rule_positions(list);
    let insert_at = remaining
        .get(to)
        .copied()
        .unwrap_or_else(|| remaining.last().map_or(0, |last| last.saturating_add(1)));
    list.children.insert(insert_at, moved);
    for child in &mut list.children {
        if words(&child.tokens)
            .first()
            .is_none_or(|word| word != "rule")
        {
            continue;
        }
        let Some(Token::Word(number)) = child.tokens.get_mut(1) else {
            continue;
        };
        if let Ok(old) = number.parse::<usize>() {
            *number = renumbered(old, from, to).to_string();
        }
    }
}

/// The new number of rule `old` after rule `from` moved to `to`.
const fn renumbered(old: usize, from: usize, to: usize) -> usize {
    if old == from {
        to
    } else if from < to && from < old && old <= to {
        old.saturating_sub(1)
    } else if to < from && to <= old && old < from {
        old.saturating_add(1)
    } else {
        old
    }
}

/// Indexes of the list's permit and deny lines, in order.
fn rule_positions(list: &Node) -> Vec<usize> {
    list.children
        .iter()
        .enumerate()
        .filter(|(_, child)| {
            words(&child.tokens)
                .first()
                .is_some_and(|word| word == "permit" || word == "deny")
        })
        .map(|(position, _)| position)
        .collect()
}

/// Whether `child` is the `property` line of rule `index`.
fn is_property(child: &Node, index: &str, property: &str) -> bool {
    matches!(
        words(&child.tokens).as_slice(),
        [rule, number, keyword, ..] if rule == "rule" && number == index && keyword == property
    )
}
