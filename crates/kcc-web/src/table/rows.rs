//! Tables of typed rows: filtered by a text query, sorted by a column, cut into pages.
//!
//! A table reads `?q=&sort=&dir=&page=` into a [`TableQuery`]. [`Table::new`] keeps the
//! rows that [`Row::matches`] the filter, sorts them by the [`Row::key`] of the sorted
//! column and cuts the requested page with the [`Pager`]; the sort headers and the page
//! links keep the filter, and the page links keep the sort.

use core::cmp::Reverse;

use serde::Deserialize;

use super::{Direction, Sort, SortHeader, pager::Pager};

/// Longest filter text a table reads, in characters.
const FILTER_CHARS: usize = 100;

/// A value a column sorts by: numbers before text, a missing value last.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SortKey {
    /// A number.
    Number(i128),
    /// Text, already lowercase so it sorts without regard to case.
    Text(String),
    /// No value.
    Missing,
}

impl SortKey {
    /// Text that sorts without regard to case.
    #[must_use]
    pub(crate) fn text(value: &str) -> Self {
        Self::Text(value.to_lowercase())
    }
}

/// A row of a sortable, filterable table.
pub(crate) trait Row {
    /// The columns the table sorts by, in header order.
    const COLUMNS: &'static [&'static str];

    /// The order the table starts in.
    const DEFAULT: Sort;

    /// The value of `column` this row sorts by.
    fn key(&self, column: &str) -> SortKey;

    /// Whether the row matches `needle`, which is lowercase and not empty.
    fn matches(&self, needle: &str) -> bool;
}

/// A table's request: `?q=&sort=&dir=&page=`; a malformed or unknown value falls back to
/// the table's default.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct TableQuery {
    /// Filter text, the `q` parameter.
    #[serde(default, rename = "q")]
    filter: Option<String>,
    /// Sorted column.
    #[serde(default)]
    sort: Option<String>,
    /// Sort direction, `asc` or `desc`.
    #[serde(default)]
    dir: Option<String>,
    /// Requested page, from 1.
    #[serde(default)]
    page: Option<String>,
}

/// One page of a filtered, sorted table.
#[derive(Debug, Clone)]
pub(crate) struct Table<R> {
    /// The rows of the shown page.
    rows: Vec<R>,
    /// The sort order.
    sort: Sort,
    /// The filter text, trimmed; empty for none.
    filter: String,
    /// Rows matching the filter.
    matched: usize,
    /// Rows before filtering.
    total: usize,
    /// The page and its neighbours.
    pager: Pager,
    /// Path of the table's page.
    base: String,
}

impl<R: Row> Table<R> {
    /// The page `query` asks for of `rows`, for the table page at `base`.
    #[must_use]
    pub(crate) fn new(rows: Vec<R>, query: &TableQuery, base: String) -> Self {
        let total = rows.len();
        let filter: String = query
            .filter
            .as_deref()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(FILTER_CHARS)
            .collect();
        let needle = filter.to_lowercase();
        let mut kept: Vec<R> = rows
            .into_iter()
            .filter(|row| needle.is_empty() || row.matches(&needle))
            .collect();
        let sort = Sort::parse(
            query.sort.as_deref(),
            query.dir.as_deref(),
            R::COLUMNS,
            R::DEFAULT,
        );
        let column = sort.column();
        match sort.direction() {
            Direction::Ascending => kept.sort_by_cached_key(|row| row.key(column)),
            Direction::Descending => kept.sort_by_cached_key(|row| Reverse(row.key(column))),
        }
        let matched = kept.len();
        let mut links = Vec::new();
        if !filter.is_empty() {
            links.push(("q".to_owned(), filter.clone()));
        }
        links.push(("sort".to_owned(), sort.column().to_owned()));
        links.push(("dir".to_owned(), sort.direction().param().to_owned()));
        let requested = query
            .page
            .as_deref()
            .and_then(|page| page.parse().ok())
            .unwrap_or(1);
        let (page, pager) = Pager::paginate(kept, requested, base.clone(), links);
        Self {
            rows: page,
            sort,
            filter,
            matched,
            total,
            pager,
            base,
        }
    }

    /// The rows of the shown page.
    #[must_use]
    pub(crate) fn rows(&self) -> &[R] {
        &self.rows
    }

    /// The header cell of `column`: its `aria-sort` state and the link sorting by it,
    /// which keeps the filter.
    #[must_use]
    pub(crate) fn header(&self, column: &'static str) -> SortHeader {
        if self.filter.is_empty() {
            self.sort.header(&self.base, column)
        } else {
            self.sort
                .header_keeping(&self.base, column, &[("q", &self.filter)])
        }
    }

    /// The sort order.
    #[must_use]
    pub(crate) const fn sort(&self) -> Sort {
        self.sort
    }

    /// The filter text; empty for none.
    #[must_use]
    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    /// The page and its neighbours.
    #[must_use]
    pub(crate) const fn pager(&self) -> &Pager {
        &self.pager
    }

    /// Rows matching the filter.
    #[must_use]
    pub(crate) const fn matched(&self) -> usize {
        self.matched
    }

    /// Rows before filtering.
    #[must_use]
    pub(crate) const fn total(&self) -> usize {
        self.total
    }

    /// Path of the table's page.
    #[must_use]
    pub(crate) fn base(&self) -> &str {
        &self.base
    }
}

#[cfg(test)]
impl TableQuery {
    /// The parameters as read: `q`, `sort`, `dir` and `page`.
    pub(crate) fn parts(&self) -> [Option<&str>; 4] {
        [
            self.filter.as_deref(),
            self.sort.as_deref(),
            self.dir.as_deref(),
            self.page.as_deref(),
        ]
    }
}

#[cfg(test)]
#[path = "rows_tests.rs"]
mod tests;
