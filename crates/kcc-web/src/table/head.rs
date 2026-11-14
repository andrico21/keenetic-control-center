//! The parts of a rendered table above its rows: the filter box and the header cells.

use super::{
    Sort, SortHeader,
    rows::{Row, Table},
};

/// The filter box of a table: its label and the state it keeps.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Search {
    /// The localized label.
    label: String,
    /// Path of the table's page.
    base: String,
    /// The filter text.
    filter: String,
    /// The sort order.
    sort: Sort,
}

/// One header cell: sortable, plain, or a hidden label over the actions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct Head {
    /// The localized label.
    label: String,
    /// The sort link and state of a sortable column.
    sort: Option<SortHeader>,
    /// The class of a plain header cell.
    class: Option<&'static str>,
    /// Whether the label is for screen readers only.
    hidden: bool,
}

impl Search {
    /// The filter box labelled `label` over `table`.
    pub(crate) fn over<R>(label: String, table: &Table<R>) -> Self
    where
        R: Row,
    {
        Self {
            label,
            base: table.base().to_owned(),
            filter: table.filter().to_owned(),
            sort: table.sort(),
        }
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Path of the table's page.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The filter text.
    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    /// The sort order.
    pub(crate) const fn sort(&self) -> Sort {
        self.sort
    }
}

impl Head {
    /// A column sorted through `sort`.
    pub(crate) const fn sorted(label: String, sort: SortHeader) -> Self {
        Self {
            label,
            sort: Some(sort),
            class: None,
            hidden: false,
        }
    }

    /// A column that does not sort.
    pub(crate) const fn plain(label: String) -> Self {
        Self {
            label,
            sort: None,
            class: None,
            hidden: false,
        }
    }

    /// The column over the row actions, labelled for screen readers.
    pub(crate) const fn hidden(label: String) -> Self {
        Self {
            label,
            sort: None,
            class: None,
            hidden: true,
        }
    }

    /// The plain column with the class `class`.
    pub(crate) const fn with_class(mut self, class: &'static str) -> Self {
        self.class = Some(class);
        self
    }

    /// The localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// The sort link and state of a sortable column.
    pub(crate) const fn sort(&self) -> Option<&SortHeader> {
        self.sort.as_ref()
    }

    /// The class of a plain header cell.
    pub(crate) const fn class_name(&self) -> Option<&'static str> {
        self.class
    }

    /// Whether the label is for screen readers only.
    pub(crate) const fn is_hidden(&self) -> bool {
        self.hidden
    }
}
