//! What the DNS and VPN pages render: tables of cells with row actions, panels of
//! settings, and the region holding both, which a change sends again out of band.

use askama::Template;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    table::{acts::Act, cells::Cell, view::TableView},
};

/// One panel: a title with an optional state, a note, settings, items and actions.
#[derive(Debug)]
pub(crate) struct Panel {
    /// Heading id.
    id: String,
    /// The localized title.
    title: String,
    /// The state pill: `data-status` and label.
    pill: Option<(String, String)>,
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
            .map(|status| (status.to_owned(), cell.shown_text()));
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

localized!(Region);
fragment!(Region);

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
