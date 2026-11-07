//! Word-oriented matching for flattened configuration commands.

/// Matches a complete flattened command against a group pattern.
pub(super) fn matches(pattern: &str, words: &[&str]) -> bool {
    let pattern_words = pattern.split_whitespace().collect::<Vec<_>>();
    match_parts(&pattern_words, words)
}

/// Matches a pattern to a catalog path, ignoring object-value wildcard slots.
pub(super) fn matches_catalog(pattern: &str, path: &str) -> bool {
    let literals = pattern
        .split_whitespace()
        .filter(|part| *part != "**" && !part.contains('*'));
    let mut path_words = path.split_whitespace();
    literals.into_iter().all(|expected| {
        path_words
            .by_ref()
            .any(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

/// Recursively evaluates one-word, prefix, and remaining-word wildcards.
fn match_parts(pattern: &[&str], words: &[&str]) -> bool {
    match (pattern, words) {
        ([], []) => true,
        ([], [_first, ..]) => false,
        (["**", rest @ ..], remaining) => {
            match_parts(rest, remaining)
                || remaining
                    .split_first()
                    .is_some_and(|(_first, tail)| match_parts(pattern, tail))
        }
        ([_first, ..], []) => false,
        ([expected, rest @ ..], [actual, tail @ ..]) => {
            segment_matches(expected, actual) && match_parts(rest, tail)
        }
    }
}

/// Matches one exact, wildcard, or prefix-wildcard word.
fn segment_matches(pattern: &str, actual: &str) -> bool {
    pattern == "*"
        || pattern.eq_ignore_ascii_case(actual)
        || pattern.split_once('*').is_some_and(|(prefix, suffix)| {
            actual
                .get(..prefix.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
                && actual
                    .get(actual.len().saturating_sub(suffix.len())..)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
        })
}
