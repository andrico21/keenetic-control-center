//! The routers table of a section's landing page: each router the role may read, linked
//! to its dashboard, beside the section's pages on it.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{cells::Cell, head::Head, piece::Piece, view::TableView};

/// The routers table in `locale` whose second column reads `column`: one row per router
/// id and its pages cell, or a note in its place while fleet services are missing
/// (`None`) or no router shows.
pub(crate) fn routers_table(
    (locale, column): (Locale, MessageKey),
    routers: Option<Vec<(String, Cell)>>,
) -> TableView {
    let blank = TableView::new("table").compact();
    let Some(listed) = routers else {
        return blank.blank("page__text", tr(locale, keys::WEB_FLEET_UNAVAILABLE, None));
    };
    if listed.is_empty() {
        return blank.blank(
            "page__text",
            tr(locale, keys::WEB_EXPLORER_LANDING_EMPTY, None),
        );
    }
    let mut view = blank
        .head(Head::plain(tr(locale, keys::WEB_EXPLORER_ROUTER, None)))
        .head(Head::plain(tr(locale, column, None)));
    for (router, pages) in listed {
        let link = Piece::link(format!("/ui/r/{router}"), router);
        view = view.row(vec![Cell::of(vec![link]), pages]);
    }
    view
}
