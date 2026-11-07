//! Ranked search over visible catalog commands.

use core::cmp::Reverse;

use crate::{
    Catalog,
    search::{SearchResult, expand, score, tokenize},
};

/// Applies the established query scoring and deterministic tie breaker.
pub(super) fn search<'catalog>(
    catalog: &'catalog Catalog,
    query: &str,
    limit: usize,
) -> Vec<SearchResult<'catalog>> {
    if limit == 0 {
        return Vec::new();
    }
    let query_tokens = tokenize(query);
    if query_tokens.is_empty() {
        return Vec::new();
    }
    let expanded = expand(&query_tokens);
    let mut results = catalog
        .commands()
        .filter_map(|command| {
            score(command, &query_tokens, &expanded)
                .filter(|value| *value > 0)
                .map(|value| SearchResult {
                    command,
                    score: value,
                })
        })
        .collect::<Vec<_>>();
    results.sort_by_key(|result| (Reverse(result.score), result.command.path.as_str()));
    results.truncate(limit);
    results
}
