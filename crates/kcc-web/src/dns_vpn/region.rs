//! What the DNS and VPN pages render: tables of cells with row actions, panels of
//! settings, and the region holding both, which a change sends again out of band.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    cells::{Act, Cell},
    listing::{Line, Listing},
};
use crate::{
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
    table::{Sort, SortHeader, pager::Pager, rows::Table},
};

/// One table of a tab, as rendered: one page of rows with the filter and sort state.
#[derive(Debug)]
pub(crate) struct TableView {
    /// The table's accessible name.
    label: String,
    /// What an empty table says, offering the next action.
    empty: String,
    /// Header labels and their sort links.
    headers: Vec<(String, SortHeader)>,
    /// Row header ids, cells and actions of the shown page.
    rows: Vec<(String, Vec<Cell>, Vec<Act>)>,
    /// Whether any row has actions.
    actions: bool,
    /// Path of the tab.
    base: String,
    /// The filter text.
    filter: String,
    /// The sort order.
    sort: Sort,
    /// The page and its neighbours.
    pager: Pager,
    /// "N of M" while a filter is set.
    count: String,
    /// Rows before filtering.
    total: usize,
}

impl TableView {
    /// The shown page of `table`, an `listing` table, in `locale`.
    pub(crate) fn of<L>(listing: &L, table: &Table<Line<L>>, locale: Locale) -> Self
    where
        L: Listing,
    {
        let headers = L::COLUMNS
            .iter()
            .zip(L::LABELS)
            .map(|(column, key)| (tr(locale, *key, None), table.header(column)))
            .collect();
        let rows: Vec<(String, Vec<Cell>, Vec<Act>)> = table
            .rows()
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let (cells, actions) = line.parts();
                (format!("row-{}", index.saturating_add(1)), cells, actions)
            })
            .collect();
        let mut args = FluentArgs::new();
        args.set("count", table.matched());
        args.set("total", table.total());
        Self {
            label: tr(locale, listing.name(), None),
            empty: tr(locale, listing.empty(), None),
            headers,
            actions: rows.iter().any(|(_, _, actions)| !actions.is_empty()),
            rows,
            base: table.base().to_owned(),
            filter: table.filter().to_owned(),
            sort: table.sort(),
            pager: table.pager().clone(),
            count: tr(locale, keys::WEB_KIT_TABLE_COUNT, Some(&args)),
            total: table.total(),
        }
    }

    /// Path of the tab, for the filter form.
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

    /// The page and its neighbours.
    pub(crate) const fn pager(&self) -> &Pager {
        &self.pager
    }
}

/// One panel: a title with an optional state, a note, settings, items and actions.
#[derive(Debug)]
pub(crate) struct Panel {
    /// Heading id.
    id: String,
    /// The localized title.
    title: String,
    /// The state pill: `data-status` and label.
    pill: Option<(&'static str, String)>,
    /// A localized note under the title.
    note: String,
    /// Settings: id, label, value, Edit dialog.
    rows: Vec<(String, String, Option<String>, Option<String>)>,
    /// Identifiers listed under the settings.
    items: Vec<String>,
    /// The panel's actions.
    actions: Vec<Act>,
}

impl Panel {
    /// An empty panel `id` titled `title`.
    pub(crate) fn new(locale: Locale, id: &str, title: MessageKey) -> Self {
        Self {
            id: id.to_owned(),
            title: tr(locale, title, None),
            pill: None,
            note: String::new(),
            rows: Vec::new(),
            items: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Shows the state `cell` (a [`Cell::pill`]) beside the title.
    pub(crate) fn state(mut self, cell: &Cell) -> Self {
        self.pill = cell
            .status()
            .map(|status| (status, cell.shown_text().to_owned()));
        self
    }

    /// Adds the note `text`.
    pub(crate) fn note(mut self, text: String) -> Self {
        self.note = text;
        self
    }

    /// Adds the setting `label` showing `value`, with Edit opening `edit` when given.
    pub(crate) fn row(
        mut self,
        (locale, label): (Locale, MessageKey),
        value: Option<String>,
        edit: Option<String>,
    ) -> Self {
        let id = format!("{}-{}", self.id, self.rows.len());
        self.rows.push((id, tr(locale, label, None), value, edit));
        self
    }

    /// Lists `items` under the settings.
    pub(crate) fn items(mut self, items: Vec<String>) -> Self {
        self.items = items;
        self
    }

    /// Adds the action `act`.
    pub(crate) fn act(mut self, act: Act) -> Self {
        self.actions.push(act);
        self
    }
}

/// The region of a tab: a read problem, panels and a table.
#[derive(Template)]
#[template(path = "partials/dns_vpn_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Why the router could not be read; empty when it was.
    problem: String,
    /// Panels above the table.
    panels: Vec<Panel>,
    /// The table.
    table: Option<TableView>,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

impl Localize for Region {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Region {
    /// An empty region in `locale`.
    pub(crate) const fn new(locale: Locale) -> Self {
        Self {
            shell: fragment_shell(locale),
            problem: String::new(),
            panels: Vec::new(),
            table: None,
            oob: false,
        }
    }

    /// A region saying why the router could not be read: the localized `reason`.
    pub(crate) fn failed(locale: Locale, reason: String) -> Self {
        Self {
            problem: reason,
            ..Self::new(locale)
        }
    }

    /// Adds `panel`.
    pub(crate) fn panel(mut self, panel: Panel) -> Self {
        self.panels.push(panel);
        self
    }

    /// Shows `table`.
    pub(crate) fn table(mut self, table: TableView) -> Self {
        self.table = Some(table);
        self
    }

    /// The region as an out-of-band replacement of the page's.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}
