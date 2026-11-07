//! The lines that changed between two configurations.
//!
//! A shortest edit script over the two line sequences (Myers' greedy algorithm, never
//! stepping past either end), grouped into hunks of removed and added lines. Its trace
//! grows with the square of the edits, so past [`MAX_EDITS`] the lines compare as
//! multisets instead: still exactly the removed and the added lines, but a line that only
//! moved is not shown then.

use alloc::collections::BTreeMap;
use core::{iter, mem};

/// Most edits an ordered script is computed for.
const MAX_EDITS: usize = 1_000;

/// One step of an edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The line is in both sequences.
    Keep,
    /// The older line is gone.
    Remove,
    /// The newer line is new.
    Add,
}

/// The furthest point of each diagonal after one round of edits: the older-sequence
/// position, or `None` when the diagonal is out of reach.
type Frontier = Vec<Option<usize>>;

/// A run of changed lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Hunk {
    /// Removed lines, as indices into the older sequence.
    removed: Vec<usize>,
    /// Added lines, as indices into the newer sequence.
    added: Vec<usize>,
}

impl Hunk {
    /// Removed lines, as indices into the older sequence.
    pub(crate) fn removed(&self) -> &[usize] {
        &self.removed
    }

    /// Added lines, as indices into the newer sequence.
    pub(crate) fn added(&self) -> &[usize] {
        &self.added
    }

    /// Whether nothing changed in it.
    const fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty()
    }
}

/// The changes turning one sequence into another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Changes {
    /// The hunks, in order.
    hunks: Vec<Hunk>,
    /// Whether the order of lines was compared.
    ordered: bool,
}

impl Changes {
    /// The changes turning `old` into `new`.
    pub(crate) fn between<T>(old: &[T], new: &[T]) -> Self
    where
        T: Ord,
    {
        script(old, new, MAX_EDITS).map_or_else(
            || Self {
                hunks: Some(unordered(old, new))
                    .filter(|hunk| !hunk.is_empty())
                    .into_iter()
                    .collect(),
                ordered: false,
            },
            |steps| Self {
                hunks: hunks(&steps),
                ordered: true,
            },
        )
    }

    /// The hunks, in order.
    pub(crate) fn hunks(&self) -> &[Hunk] {
        &self.hunks
    }

    /// Whether the order of lines was compared; `false` for a very large difference.
    pub(crate) const fn ordered(&self) -> bool {
        self.ordered
    }

    /// How many lines were removed.
    pub(crate) fn removed(&self) -> usize {
        self.hunks.iter().map(|hunk| hunk.removed.len()).sum()
    }

    /// How many lines were added.
    pub(crate) fn added(&self) -> usize {
        self.hunks.iter().map(|hunk| hunk.added.len()).sum()
    }
}

/// The shortest edit script from `old` to `new`, or `None` when it takes more than
/// `limit` edits.
fn script<T>(old: &[T], new: &[T], limit: usize) -> Option<Vec<Step>>
where
    T: Eq,
{
    let ends = (old.len(), new.len());
    let mut trace: Vec<Frontier> = Vec::new();
    for edits in 0..=limit {
        let mut frontier = Frontier::new();
        let mut done = false;
        for slot in 0..=edits.saturating_mul(2) {
            let reached = arrive(trace.last().map(Vec::as_slice), edits, slot, ends)
                .and_then(|(start, _down)| slide(old, new, (start, edits, slot)));
            done |= reached.is_some_and(|x| x == ends.0 && row(x, edits, slot) == Some(ends.1));
            frontier.push(reached);
        }
        trace.push(frontier);
        if done {
            return Some(backtrack(&trace, ends));
        }
    }
    None
}

/// The newer-sequence position of older position `x` on diagonal `slot` of round `edits`.
fn row(x: usize, edits: usize, slot: usize) -> Option<usize> {
    x.checked_add(edits)?.checked_sub(slot)
}

/// Where diagonal `slot` of round `edits` starts, and whether it got there by adding a line.
///
/// It is the further of a step down from the diagonal above and a step right from the one
/// below, each only while the line it takes exists.
fn arrive(
    previous: Option<&[Option<usize>]>,
    edits: usize,
    slot: usize,
    (old_len, new_len): (usize, usize),
) -> Option<(usize, bool)> {
    let Some(before) = previous else {
        return Some((0, false));
    };
    let last = edits.checked_sub(1)?;
    let down = before
        .get(slot)
        .copied()
        .flatten()
        .filter(|&x| row(x, last, slot).is_some_and(|y| y < new_len));
    let right = slot
        .checked_sub(2)
        .and_then(|below| before.get(below).copied().flatten())
        .filter(|&x| x < old_len)
        .map(|x| x.saturating_add(1));
    match (down, right) {
        (Some(x), Some(further)) if further > x => Some((further, false)),
        (Some(x), _) => Some((x, true)),
        (None, Some(further)) => Some((further, false)),
        (None, None) => None,
    }
}

/// The end of the run of equal lines from `start` on diagonal `slot` of round `edits`.
fn slide<T>(old: &[T], new: &[T], (start, edits, slot): (usize, usize, usize)) -> Option<usize>
where
    T: Eq,
{
    let mut x = start;
    let mut y = row(start, edits, slot)?;
    while let (Some(left), Some(right)) = (old.get(x), new.get(y))
        && left == right
    {
        x = x.saturating_add(1);
        y = y.saturating_add(1);
    }
    Some(x)
}

/// The steps of the path that reached `ends` in the last round of `trace`.
fn backtrack(trace: &[Frontier], ends: (usize, usize)) -> Vec<Step> {
    let mut steps = Vec::new();
    let (mut x, mut y) = ends;
    for edits in (1..trace.len()).rev() {
        let slot = x.saturating_add(edits).saturating_sub(y);
        let previous = trace.get(edits.saturating_sub(1)).map(Vec::as_slice);
        let Some((start, down)) = arrive(previous, edits, slot, ends) else {
            break;
        };
        let start_row = row(start, edits, slot).unwrap_or(y);
        while x > start && y > start_row {
            steps.push(Step::Keep);
            x = x.saturating_sub(1);
            y = y.saturating_sub(1);
        }
        if down {
            steps.push(Step::Add);
            y = start_row.saturating_sub(1);
        } else {
            steps.push(Step::Remove);
            y = start_row;
        }
        x = if down { start } else { start.saturating_sub(1) };
    }
    steps.extend(iter::repeat_n(Step::Keep, x));
    steps.reverse();
    steps
}

/// The script's changed lines, grouped into hunks between kept lines.
fn hunks(steps: &[Step]) -> Vec<Hunk> {
    let mut found = Vec::new();
    let mut current = Hunk::default();
    let (mut old, mut new) = (0_usize, 0_usize);
    for step in steps {
        match step {
            Step::Keep => {
                if !current.is_empty() {
                    found.push(mem::take(&mut current));
                }
                old = old.saturating_add(1);
                new = new.saturating_add(1);
            }
            Step::Remove => {
                current.removed.push(old);
                old = old.saturating_add(1);
            }
            Step::Add => {
                current.added.push(new);
                new = new.saturating_add(1);
            }
        }
    }
    if !current.is_empty() {
        found.push(current);
    }
    found
}

/// The lines of `old` and `new` that the other one does not hold as often.
fn unordered<T>(old: &[T], new: &[T]) -> Hunk
where
    T: Ord,
{
    Hunk {
        removed: missing(old, new),
        added: missing(new, old),
    }
}

/// The indices of the lines of `from` that `to` does not hold as often.
fn missing<T>(from: &[T], to: &[T]) -> Vec<usize>
where
    T: Ord,
{
    let mut left: BTreeMap<&T, usize> = BTreeMap::new();
    for line in to {
        let count = left.entry(line).or_default();
        *count = count.saturating_add(1);
    }
    from.iter()
        .enumerate()
        .filter_map(|(index, line)| match left.get_mut(line) {
            Some(count) if *count > 0 => {
                *count = count.saturating_sub(1);
                None
            }
            Some(_) | None => Some(index),
        })
        .collect()
}

#[cfg(test)]
#[path = "diff_tests.rs"]
mod tests;
