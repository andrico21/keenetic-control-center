//! Unit tests of the line diff: every script is a shortest one and rebuilds the newer
//! sequence, hunks split at kept lines, and the multiset comparison past the limit.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use core::error::Error;

use super::{Changes, Hunk, Step, script, unordered};

/// Every sequence over `{0, 1}` of at most four elements.
fn sequences() -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut layer: Vec<Vec<u8>> = vec![Vec::new()];
    for _ in 0..4_u8 {
        layer = layer
            .iter()
            .flat_map(|sequence| {
                [0_u8, 1].map(|bit| {
                    let mut longer = sequence.clone();
                    longer.push(bit);
                    longer
                })
            })
            .collect();
        all.extend(layer.iter().cloned());
    }
    all
}

/// The length of a longest common subsequence, by exhaustive recursion.
fn common(left: &[u8], right: &[u8]) -> usize {
    match (left.split_first(), right.split_first()) {
        (Some((first, rest)), Some((other, others))) if first == other => {
            common(rest, others).saturating_add(1)
        }
        (Some((_, rest)), Some((_, others))) => common(rest, right).max(common(left, others)),
        (None, _) | (_, None) => 0,
    }
}

/// `new` rebuilt from `old` and the script, or `None` when the script does not fit.
fn rebuild(old: &[u8], new: &[u8], steps: &[Step]) -> Option<Vec<u8>> {
    let mut built = Vec::new();
    let (mut from, mut to) = (0_usize, 0_usize);
    for step in steps {
        match step {
            Step::Keep => {
                let kept = *old.get(from)?;
                (new.get(to)? == &kept).then_some(())?;
                built.push(kept);
                from = from.saturating_add(1);
                to = to.saturating_add(1);
            }
            Step::Remove => {
                from = old.get(from).map(|_| from.saturating_add(1))?;
            }
            Step::Add => {
                built.push(*new.get(to)?);
                to = to.saturating_add(1);
            }
        }
    }
    (from == old.len() && to == new.len()).then_some(built)
}

#[test]
fn every_script_is_shortest_and_rebuilds_the_newer_sequence() -> Result<(), Box<dyn Error>> {
    let all = sequences();
    assert_eq!(all.len(), 31, "every sequence up to four elements");
    for old in &all {
        for new in &all {
            let steps = script(old, new, 16).ok_or("a short script exists")?;
            assert_eq!(
                rebuild(old, new, &steps).as_deref(),
                Some(new.as_slice()),
                "{old:?} -> {new:?}"
            );
            let edits = steps.iter().filter(|step| **step != Step::Keep).count();
            let shortest = old
                .len()
                .saturating_add(new.len())
                .saturating_sub(common(old, new).saturating_mul(2));
            assert_eq!(edits, shortest, "{old:?} -> {new:?}: {steps:?}");
        }
    }
    Ok(())
}

#[test]
fn changed_lines_group_into_hunks_between_kept_lines() {
    let old = ["a", "b", "c", "d"];
    let new = ["a", "x", "c", "d", "e"];
    let changes = Changes::between(&old, &new);
    assert!(changes.ordered(), "a small difference keeps the order");
    assert_eq!(
        changes.hunks(),
        [
            Hunk {
                removed: vec![1],
                added: vec![1],
            },
            Hunk {
                removed: Vec::new(),
                added: vec![4],
            },
        ],
        "b became x, e was added"
    );
    assert_eq!((changes.removed(), changes.added()), (1, 2), "counts");
    assert!(Changes::between(&old, &old).hunks().is_empty(), "no change");
}

#[test]
fn a_moved_line_shows_as_removed_and_added_in_order_only() {
    let old = ["a", "b", "c"];
    let new = ["b", "c", "a"];
    let changes = Changes::between(&old, &new);
    assert_eq!((changes.removed(), changes.added()), (1, 1), "a moved");
    assert_eq!(
        unordered(&old, &new),
        Hunk::default(),
        "as multisets nothing changed"
    );
}

#[test]
fn past_the_limit_lines_compare_as_multisets() {
    let old = ["a", "b", "b", "c"];
    let new = ["b", "d", "a"];
    assert_eq!(script(&old, &new, 2), None, "more than two edits");
    assert_eq!(
        unordered(&old, &new),
        Hunk {
            removed: vec![2, 3],
            added: vec![1],
        },
        "one b and c went, d came"
    );
}
