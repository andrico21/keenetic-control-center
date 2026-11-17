//! "Did you mean" suggestions for unknown request fields.

/// Returns the nearest sibling if its adjacent-transposition distance is at most two.
pub(super) fn nearest(field: &str, siblings: &[&str]) -> Option<String> {
    nearest_by(field, siblings, damerau_levenshtein)
}

/// Returns the sibling nearest to `field` by `measure`, if it is at most two.
///
/// A field longer than every sibling by more than two characters is at least that far
/// from each of them, so no distance is computed for it: the work stays bounded by the
/// siblings, not by the caller's field.
fn nearest_by(
    field: &str,
    siblings: &[&str],
    mut measure: impl FnMut(&str, &str) -> usize,
) -> Option<String> {
    let longest = siblings
        .iter()
        .map(|sibling| sibling.chars().count())
        .max()?;
    if field.chars().nth(longest.saturating_add(2)).is_some() {
        return None;
    }
    siblings
        .iter()
        .filter_map(|candidate| {
            let distance = measure(field, candidate);
            (distance <= 2).then_some((distance, *candidate))
        })
        .min()
        .map(|(_distance, candidate)| candidate.to_owned())
}

/// Computes optimal-string-alignment Damerau-Levenshtein distance.
fn damerau_levenshtein(left: &str, right: &str) -> usize {
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let columns = right_chars.len().saturating_add(1);
    let mut matrix = vec![0; left_chars.len().saturating_add(1).saturating_mul(columns)];
    for row in 0..=left_chars.len() {
        if let Some(cell) = matrix.get_mut(row.saturating_mul(columns)) {
            *cell = row;
        }
    }
    for column in 0..=right_chars.len() {
        if let Some(cell) = matrix.get_mut(column) {
            *cell = column;
        }
    }
    for row in 1..=left_chars.len() {
        for column in 1..=right_chars.len() {
            let index = row.saturating_mul(columns).saturating_add(column);
            let deletion = matrix
                .get(index.saturating_sub(columns))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let insertion = matrix
                .get(index.saturating_sub(1))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let substitution = matrix
                .get(index.saturating_sub(columns).saturating_sub(1))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(usize::from(
                    row.checked_sub(1).and_then(|offset| left_chars.get(offset))
                        != column
                            .checked_sub(1)
                            .and_then(|offset| right_chars.get(offset)),
                ));
            let mut distance = deletion.min(insertion).min(substitution);
            if row > 1
                && column > 1
                && row.checked_sub(1).and_then(|offset| left_chars.get(offset))
                    == column
                        .checked_sub(2)
                        .and_then(|offset| right_chars.get(offset))
                && row.checked_sub(2).and_then(|offset| left_chars.get(offset))
                    == column
                        .checked_sub(1)
                        .and_then(|offset| right_chars.get(offset))
            {
                distance = distance.min(
                    matrix
                        .get(
                            index
                                .saturating_sub(columns.saturating_mul(2))
                                .saturating_sub(2),
                        )
                        .copied()
                        .unwrap_or(usize::MAX)
                        .saturating_add(1),
                );
            }
            if let Some(cell) = matrix.get_mut(index) {
                *cell = distance;
            }
        }
    }
    matrix.last().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::{damerau_levenshtein, nearest_by};

    /// A-11: a field longer than every sibling by more than two cannot be within distance two,
    /// so no distance is computed for it, however long it is; a close field still gets one.
    #[test]
    #[expect(clippy::missing_panics_doc, reason = "a test fails by panicking")]
    fn an_overlong_field_computes_no_distance() {
        let siblings = ["host", "hostname"];
        let calls = Cell::new(0_usize);
        let counted = |left: &str, right: &str| {
            calls.set(calls.get() + 1);
            damerau_levenshtein(left, right)
        };
        assert_eq!(nearest_by(&"x".repeat(11), &siblings, counted), None);
        assert_eq!(calls.get(), 0);
        assert_eq!(
            nearest_by("hostnamexx", &siblings, damerau_levenshtein).as_deref(),
            Some("hostname")
        );
    }
}
