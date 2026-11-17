//! The commands that differ between two configurations, compared in order.

/// Most cells of the comparison table; a larger difference is refused, never guessed.
const MAX_CELLS: usize = 16_000_000;

/// The positions that differ between an older and a newer sequence.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Changes {
    /// Positions in the older sequence that are gone, in order.
    removed: Vec<usize>,
    /// Positions in the newer sequence that are new, in order.
    added: Vec<usize>,
}

impl Changes {
    /// Positions in the older sequence that are gone, in order.
    pub(crate) fn removed(&self) -> &[usize] {
        &self.removed
    }

    /// Positions in the newer sequence that are new, in order.
    pub(crate) fn added(&self) -> &[usize] {
        &self.added
    }
}

/// The shortest set of removed and added positions that turns `old` into `new`, keeping
/// the order of the lines both hold, or `None` when the two differ too much to compare.
pub(crate) fn between<T>(old: &[T], new: &[T]) -> Option<Changes>
where
    T: Eq,
{
    let prefix = old
        .iter()
        .zip(new)
        .take_while(|(older, newer)| older == newer)
        .count();
    let (old_rest, new_rest) = (old.get(prefix..)?, new.get(prefix..)?);
    let suffix = old_rest
        .iter()
        .rev()
        .zip(new_rest.iter().rev())
        .take_while(|(older, newer)| older == newer)
        .count();
    let old_middle = old_rest.get(..old_rest.len().saturating_sub(suffix))?;
    let new_middle = new_rest.get(..new_rest.len().saturating_sub(suffix))?;
    let width = new_middle.len().saturating_add(1);
    if old_middle.len().saturating_add(1).saturating_mul(width) > MAX_CELLS {
        return None;
    }
    let table = common_lengths(old_middle, new_middle, width);
    let mut changes = Changes::default();
    let (mut i, mut j) = (0_usize, 0_usize);
    while i < old_middle.len() && j < new_middle.len() {
        if old_middle.get(i) == new_middle.get(j) {
            i = i.saturating_add(1);
            j = j.saturating_add(1);
        } else if at(&table, width, i.saturating_add(1), j)
            >= at(&table, width, i, j.saturating_add(1))
        {
            changes.removed.push(prefix.saturating_add(i));
            i = i.saturating_add(1);
        } else {
            changes.added.push(prefix.saturating_add(j));
            j = j.saturating_add(1);
        }
    }
    changes
        .removed
        .extend((i..old_middle.len()).map(|at| prefix.saturating_add(at)));
    changes
        .added
        .extend((j..new_middle.len()).map(|at| prefix.saturating_add(at)));
    Some(changes)
}

/// Longest common subsequence of every pair of suffixes, `width` cells per row.
fn common_lengths<T>(old: &[T], new: &[T], width: usize) -> Vec<u32>
where
    T: Eq,
{
    let mut table = vec![0_u32; old.len().saturating_add(1).saturating_mul(width)];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            let below = at(&table, width, i.saturating_add(1), j);
            let value = if old.get(i) == new.get(j) {
                at(&table, width, i.saturating_add(1), j.saturating_add(1)).saturating_add(1)
            } else {
                below.max(at(&table, width, i, j.saturating_add(1)))
            };
            if let Some(cell) = table.get_mut(i.saturating_mul(width).saturating_add(j)) {
                *cell = value;
            }
        }
    }
    table
}

/// The table cell at row `i`, column `j`.
fn at(table: &[u32], width: usize, i: usize, j: usize) -> u32 {
    table
        .get(i.saturating_mul(width).saturating_add(j))
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::between;

    #[test]
    fn an_edit_script_keeps_the_common_order() {
        let changes = between(&["a", "b", "c", "d"], &["a", "c", "b", "d"]);
        assert_eq!(
            changes.map(|found| (found.removed, found.added)),
            Some((vec![1], vec![2]))
        );
        let duplicate = between(&["a", "b"], &["a", "b", "b"]);
        assert_eq!(
            duplicate.map(|found| (found.removed, found.added)),
            Some((vec![], vec![2]))
        );
        let swapped_ends = between(&["x", "a"], &["a", "y"]);
        assert_eq!(
            swapped_ends.map(|found| (found.removed, found.added)),
            Some((vec![0], vec![1]))
        );
    }
}
