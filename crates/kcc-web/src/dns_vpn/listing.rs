//! The tables of the DNS and VPN tabs: typed rows of cells that the shared table module
//! filters, sorts and cuts into pages of 50, and the view of their shown page.

use core::marker::PhantomData;

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::table::{
    Sort,
    acts::Act,
    cells::{Cell, Layout},
    rows::{Row, SortKey, Table},
    view::{Head, TableView},
};

/// What one table lists: its sortable columns, their header labels, its first order, its
/// name and what it says while empty.
pub(crate) trait Listing {
    /// Column ids, in header order; every column sorts.
    const COLUMNS: &'static [&'static str];
    /// Header labels, in the same order.
    const LABELS: &'static [MessageKey];
    /// The order the table starts in.
    const DEFAULT: Sort;

    /// The table's accessible name.
    fn name(&self) -> MessageKey;

    /// What the table says while it has no rows, offering the next action.
    fn empty(&self) -> MessageKey;
}

/// One row of an `L` table: one cell per column, then the row's actions.
pub(crate) struct Line<L> {
    /// Cells in column order; the first names the row.
    cells: Vec<Cell>,
    /// What the role may do with the row.
    actions: Vec<Act>,
    /// Lowercase text of every cell, for the filter.
    search: String,
    /// The table the row belongs to.
    listing: PhantomData<fn() -> L>,
}

impl<L> Line<L> {
    /// A row of `cells`, in column order.
    pub(crate) fn new(cells: Vec<Cell>) -> Self {
        let search = cells
            .iter()
            .map(Cell::shown)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        Self {
            cells,
            actions: Vec::new(),
            search,
            listing: PhantomData,
        }
    }

    /// Adds `action` to the row.
    pub(crate) fn with(mut self, action: Act) -> Self {
        self.actions.push(action);
        self
    }
}

impl<L: Listing> Row for Line<L> {
    const COLUMNS: &'static [&'static str] = L::COLUMNS;
    const DEFAULT: Sort = L::DEFAULT;

    fn key(&self, column: &str) -> SortKey {
        L::COLUMNS
            .iter()
            .position(|name| *name == column)
            .and_then(|index| self.cells.get(index))
            .map_or(SortKey::Missing, Cell::key)
    }

    fn matches(&self, needle: &str) -> bool {
        self.search.contains(needle)
    }
}

/// The shown page of `table`, an `listing` table, in `locale`.
///
/// While the table has no rows it shows the empty text; otherwise the filter, the count
/// while a filter is set, and the page of rows, each named by its first cell and followed
/// by its actions when any row has some.
pub(crate) fn table_view<L>(listing: &L, table: &Table<Line<L>>, locale: Locale) -> TableView
where
    L: Listing,
{
    let named = TableView::new("table domain-table").labelled(tr(locale, listing.name(), None));
    if table.total() == 0 {
        return named.blank("table-empty", tr(locale, listing.empty(), None));
    }
    let mut view = named.search(tr(locale, keys::WEB_KIT_TABLE_FILTER, None), table);
    if !table.filter().is_empty() {
        let mut args = FluentArgs::new();
        args.set("count", table.matched());
        args.set("total", table.total());
        view = view.count(
            "table-count",
            tr(locale, keys::WEB_KIT_TABLE_COUNT, Some(&args)),
        );
    }
    if table.rows().is_empty() {
        return view.blank(
            "table-empty",
            tr(locale, keys::WEB_KIT_TABLE_NO_MATCH, None),
        );
    }
    for (column, key) in L::COLUMNS.iter().zip(L::LABELS) {
        view = view.head(Head::sorted(tr(locale, *key, None), table.header(column)));
    }
    let actions = table.rows().iter().any(|line| !line.actions.is_empty());
    if actions {
        view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    }
    for (index, line) in table.rows().iter().enumerate() {
        let id = format!("row-{}", index.saturating_add(1));
        let mut cells: Vec<Cell> = line.cells.clone();
        if let Some(first) = cells.first_mut() {
            *first = first.clone().head_with_id(id.clone());
        }
        if actions {
            cells.push(Cell::acts(
                Layout::Wrapped("row-actions"),
                line.actions.clone(),
                id,
            ));
        }
        view = view.row(cells);
    }
    view.paged(table.pager().clone())
}
