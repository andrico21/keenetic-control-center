//! Server-side tables: sorting, filtering and pages.
//!
//! A sortable table reads `?sort=<column>&dir=<asc|desc>`. [`Sort::parse`] validates both
//! against the table's own column list, the handler sorts the rows, and
//! [`Sort::header`] gives every header cell its `aria-sort` state and the link that
//! sorts by it. Rows are never sorted in the browser.
//!
//! [`rows::Table`] does all of it for typed rows ([`rows::Row`]): the filter, the sort and
//! the page of [`pager::PAGE_ROWS`] rows, whose [`pager::Pager`] links keep the others.

pub mod pager;
pub mod rows;

use url::form_urlencoded;

/// Sort direction of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// Smallest first.
    Ascending,
    /// Largest first.
    Descending,
}

impl Direction {
    /// The `dir` query parameter value.
    #[inline]
    #[must_use]
    pub const fn param(self) -> &'static str {
        match self {
            Self::Ascending => "asc",
            Self::Descending => "desc",
        }
    }

    /// Parses a `dir` query parameter value.
    #[inline]
    #[must_use]
    pub fn from_param(value: &str) -> Option<Self> {
        match value {
            "asc" => Some(Self::Ascending),
            "desc" => Some(Self::Descending),
            _ => None,
        }
    }

    /// The other direction.
    #[inline]
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }

    /// The `aria-sort` value of a column sorted this way.
    #[inline]
    #[must_use]
    pub const fn aria_sort(self) -> &'static str {
        match self {
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}

/// The validated sort order of one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sort {
    /// Sorted column, one of the table's own column names.
    column: &'static str,
    /// Sort direction.
    direction: Direction,
}

impl Sort {
    /// Sorts by `column` in `direction`.
    #[inline]
    #[must_use]
    pub const fn new(column: &'static str, direction: Direction) -> Self {
        Self { column, direction }
    }

    /// Reads the `sort` and `dir` query parameters. A column outside `columns` yields
    /// `default`; a missing or unknown direction is ascending.
    #[inline]
    #[must_use]
    pub fn parse(
        column: Option<&str>,
        direction: Option<&str>,
        columns: &[&'static str],
        default: Self,
    ) -> Self {
        let Some(known) =
            column.and_then(|name| columns.iter().copied().find(|candidate| *candidate == name))
        else {
            return default;
        };
        Self {
            column: known,
            direction: direction
                .and_then(Direction::from_param)
                .unwrap_or(Direction::Ascending),
        }
    }

    /// Sorted column.
    #[inline]
    #[must_use]
    pub const fn column(self) -> &'static str {
        self.column
    }

    /// Sort direction.
    #[inline]
    #[must_use]
    pub const fn direction(self) -> Direction {
        self.direction
    }

    /// The header cell of `column` in a table at `base` (a path without a query): the
    /// sorted column reverses its direction, any other column sorts ascending.
    #[inline]
    #[must_use]
    pub fn header(self, base: &str, column: &'static str) -> SortHeader {
        let sorted = self.column == column;
        let next = if sorted {
            self.direction.reversed()
        } else {
            Direction::Ascending
        };
        SortHeader {
            href: format!("{base}?sort={column}&dir={}", next.param()),
            aria_sort: if sorted {
                self.direction.aria_sort()
            } else {
                "none"
            },
        }
    }

    /// As [`Sort::header`], with the `keep` query parameters, such as a filter, carried
    /// into the link before the sort.
    #[inline]
    #[must_use]
    pub fn header_keeping(
        self,
        base: &str,
        column: &'static str,
        keep: &[(&str, &str)],
    ) -> SortHeader {
        let plain = self.header(base, column);
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in keep {
            let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
        }
        let kept = query.finish();
        if kept.is_empty() {
            return plain;
        }
        let sorting = plain
            .href
            .split_once('?')
            .map_or("", |(_, sorting)| sorting);
        SortHeader {
            href: format!("{base}?{kept}&{sorting}"),
            aria_sort: plain.aria_sort,
        }
    }
}

/// The state of one sortable header cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SortHeader {
    /// Link that sorts by the column.
    href: String,
    /// `aria-sort` value: `ascending`, `descending` or `none`.
    aria_sort: &'static str,
}

impl SortHeader {
    /// Link that sorts by the column.
    #[inline]
    #[must_use]
    pub fn href(&self) -> &str {
        &self.href
    }

    /// `aria-sort` value: `ascending`, `descending` or `none`.
    #[inline]
    #[must_use]
    pub const fn aria_sort(&self) -> &'static str {
        self.aria_sort
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{Direction, Sort};

    /// Columns of the example table.
    const COLUMNS: [&str; 2] = ["name", "address"];

    /// Default order of the example table.
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    #[test]
    fn parse_accepts_only_known_columns() {
        let sorted = Sort::parse(Some("address"), Some("desc"), &COLUMNS, DEFAULT);
        assert_eq!(sorted, Sort::new("address", Direction::Descending), "valid");
        assert_eq!(
            Sort::parse(Some("password"), Some("desc"), &COLUMNS, DEFAULT),
            DEFAULT,
            "unknown column"
        );
        assert_eq!(
            Sort::parse(Some("address"), Some("sideways"), &COLUMNS, DEFAULT),
            Sort::new("address", Direction::Ascending),
            "unknown direction"
        );
        assert_eq!(Sort::parse(None, None, &COLUMNS, DEFAULT), DEFAULT, "none");
    }

    #[test]
    fn headers_link_to_the_next_order() {
        let sort = Sort::new("name", Direction::Ascending);
        let name = sort.header("/ui/clients", "name");
        assert_eq!(name.href(), "/ui/clients?sort=name&dir=desc", "reverses");
        assert_eq!(name.aria_sort(), "ascending", "current state");
        let address = sort.header("/ui/clients", "address");
        assert_eq!(
            address.href(),
            "/ui/clients?sort=address&dir=asc",
            "ascending"
        );
        assert_eq!(address.aria_sort(), "none", "not sorted");
        assert_eq!(sort.column(), "name", "column");
        assert_eq!(sort.direction(), Direction::Ascending, "direction");
    }
}
