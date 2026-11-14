//! A table as rendered by `partials/kit_table.html`: the filter box, a count, the text
//! shown instead of an empty table, the header cells, the rows and the pager.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    Sort, SortHeader,
    cells::Cell,
    pager::Pager,
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

/// One rendered table.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct TableView {
    /// Indentation added to every line, for a table nested one level deeper.
    pad: &'static str,
    /// The filter box.
    search: Option<Search>,
    /// A count line: its class and text.
    count: Option<(&'static str, String)>,
    /// What shows instead of the table: its class and text.
    blank: Option<(&'static str, String)>,
    /// The table's class.
    class: &'static str,
    /// The table's accessible name.
    label: Option<String>,
    /// Header cells.
    heads: Vec<Head>,
    /// Rows of cells.
    rows: Vec<Vec<Cell>>,
    /// The page and its neighbours.
    pager: Option<Pager>,
}

impl Search {
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

impl TableView {
    /// An empty table of class `class`.
    pub(crate) const fn new(class: &'static str) -> Self {
        Self {
            pad: "",
            search: None,
            count: None,
            blank: None,
            class,
            label: None,
            heads: Vec::new(),
            rows: Vec::new(),
            pager: None,
        }
    }

    /// The shown page of `table` under the shared filter box, with its pager; while no
    /// row shows, a note in its place says `empty` in `locale`, or that nothing matches
    /// once a filter is set.
    pub(crate) fn filtered<R>(
        class: &'static str,
        table: &Table<R>,
        (locale, empty): (Locale, MessageKey),
    ) -> Self
    where
        R: Row,
    {
        let view = Self::new(class).search(tr(locale, keys::WEB_KIT_TABLE_FILTER, None), table);
        if !table.rows().is_empty() {
            return view.paged(table.pager().clone());
        }
        let shown = if table.filter().is_empty() {
            empty
        } else {
            keys::WEB_KIT_TABLE_NO_MATCH
        };
        view.blank("page__text", tr(locale, shown, None))
    }

    /// The shown page of `table` under a filter box labelled `label`, with the count of
    /// matching rows while a filter is set and its pager; a note in its place says
    /// `empty` while the table has no rows, or that nothing matches the filter.
    pub(crate) fn counted<R>(
        class: &'static str,
        table: &Table<R>,
        (locale, label, empty): (Locale, MessageKey, MessageKey),
    ) -> Self
    where
        R: Row,
    {
        let mut view = Self::new(class).search(tr(locale, label, None), table);
        if !table.filter().is_empty() {
            let mut args = FluentArgs::new();
            args.set("count", table.matched());
            args.set("total", table.total());
            let count = tr(locale, keys::WEB_KIT_TABLE_COUNT, Some(&args));
            view = view.count("net-region__count", count);
        }
        if table.total() == 0 {
            return view.blank("panel__note", tr(locale, empty, None));
        }
        if table.matched() == 0 {
            return view.blank(
                "panel__note",
                tr(locale, keys::WEB_KIT_TABLE_NO_MATCH, None),
            );
        }
        view.paged(table.pager().clone())
    }

    /// The table one level deeper than a region's.
    pub(crate) const fn nested(mut self) -> Self {
        self.pad = "  ";
        self
    }

    /// The table with the accessible name `label`.
    pub(crate) fn labelled(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// The filter box labelled `label` over `table`.
    pub(crate) fn search<R>(mut self, label: String, table: &Table<R>) -> Self
    where
        R: Row,
    {
        self.search = Some(Search {
            label,
            base: table.base().to_owned(),
            filter: table.filter().to_owned(),
            sort: table.sort(),
        });
        self
    }

    /// The count line of class `class` reading `text`.
    pub(crate) fn count(mut self, class: &'static str, text: String) -> Self {
        self.count = Some((class, text));
        self
    }

    /// The text of class `class` shown instead of the table.
    pub(crate) fn blank(mut self, class: &'static str, text: String) -> Self {
        self.blank = Some((class, text));
        self
    }

    /// Adds the header cell `head`.
    pub(crate) fn head(mut self, head: Head) -> Self {
        self.heads.push(head);
        self
    }

    /// Adds a row of `cells`.
    pub(crate) fn row(mut self, cells: Vec<Cell>) -> Self {
        self.rows.push(cells);
        self
    }

    /// The pager under the table.
    pub(crate) fn paged(mut self, pager: Pager) -> Self {
        self.pager = Some(pager);
        self
    }

    /// The indentation of every line.
    pub(crate) const fn pad(&self) -> &'static str {
        self.pad
    }

    /// The indentation of a line `depth` spaces into the table's region.
    pub(crate) fn indent(&self, depth: usize) -> String {
        format!("{}{}", self.pad, " ".repeat(depth))
    }

    /// The filter box.
    pub(crate) const fn search_box(&self) -> Option<&Search> {
        self.search.as_ref()
    }

    /// The count line: its class and text.
    pub(crate) const fn count_line(&self) -> Option<&(&'static str, String)> {
        self.count.as_ref()
    }

    /// What shows instead of the table: its class and text.
    pub(crate) const fn blank_text(&self) -> Option<&(&'static str, String)> {
        self.blank.as_ref()
    }

    /// The table's class.
    pub(crate) const fn class(&self) -> &'static str {
        self.class
    }

    /// The table's accessible name.
    pub(crate) fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Header cells.
    pub(crate) fn heads(&self) -> &[Head] {
        &self.heads
    }

    /// Rows of cells.
    pub(crate) fn rows(&self) -> &[Vec<Cell>] {
        &self.rows
    }

    /// The page and its neighbours.
    pub(crate) const fn pager(&self) -> Option<&Pager> {
        self.pager.as_ref()
    }
}
