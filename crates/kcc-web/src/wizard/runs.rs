//! The runs table of a wizard's landing page: each run's start time linking to its page,
//! then what it does, where, and the step it is at.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    admin_shared::Timestamp,
    table::{cells::Cell, head::Head, piece::Piece, view::TableView},
};

/// The row header of a run at `href` that started at `started`, in `locale`.
pub(crate) fn started(href: String, started: Option<Timestamp>, locale: Locale) -> Cell {
    let shown = started.map_or_else(
        || Piece::text(tr(locale, keys::WEB_MIGRATE_LIST_OPEN, None)),
        |time| Piece::time(time.iso().to_owned(), time.text().to_owned()),
    );
    Cell::of(vec![Piece::link(href, String::new()).with(shown)]).head()
}

/// The table of `rows` under the `columns` headings in `locale`, one level deeper than a
/// page's; a note saying `empty` in its place when there is no run.
pub(crate) fn runs_table(
    (columns, empty): (&[MessageKey], MessageKey),
    rows: Vec<Vec<Cell>>,
    locale: Locale,
) -> TableView {
    let mut view = TableView::new("table").nested();
    if rows.is_empty() {
        return view.blank("table-empty", tr(locale, empty, None));
    }
    for key in columns {
        view = view.head(Head::plain(tr(locale, *key, None)));
    }
    rows.into_iter().fold(view, TableView::row)
}
