//! The tables of the DNS and VPN tabs: typed rows of cells that the shared table module
//! filters, sorts and cuts into pages of 50.

use core::marker::PhantomData;

use kcc_i18n::bundle::MessageKey;

use super::cells::{Act, Cell};
use crate::table::{
    Sort,
    rows::{Row, SortKey},
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

    /// The row's cells and actions, for rendering.
    pub(crate) fn parts(&self) -> (Vec<Cell>, Vec<Act>) {
        (self.cells.clone(), self.actions.clone())
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
