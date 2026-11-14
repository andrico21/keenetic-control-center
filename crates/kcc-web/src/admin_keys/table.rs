//! The API keys table: name, role, creation and last use, and Revoke where the signed-in
//! user may.

use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::KeyRow;
use crate::{
    admin_shared::Timestamp,
    table::{
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        piece::Piece,
        view::TableView,
    },
};

/// The table of `rows` in `locale`, or a note in its place when there is none.
pub(super) fn keys(rows: &[KeyRow], locale: Locale) -> TableView {
    let mut view = TableView::new("table");
    if rows.is_empty() {
        return view.blank("page__text", tr(locale, keys::WEB_ADMIN_KEYS_EMPTY, None));
    }
    for key in [
        keys::WEB_ADMIN_KEY_NAME,
        keys::WEB_ADMIN_KEY_ROLE,
        keys::WEB_ADMIN_KEY_CREATED_AT,
        keys::WEB_ADMIN_KEY_LAST_USED,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    for (index, row) in rows.iter().enumerate() {
        let id = format!("key-{}", index.saturating_add(1));
        let time = |at: &Timestamp| Piece::time(at.iso().to_owned(), at.text().to_owned());
        let last_used = row.last_used.as_ref().map_or_else(
            || Piece::span("muted", tr(locale, keys::WEB_ADMIN_KEY_NEVER, None)),
            time,
        );
        let actions = if row.revocable {
            let revoke = Act::open(locale, keys::WEB_ADMIN_KEY_REVOKE, row.revoke_url.clone());
            Cell::acts(
                Layout::Wrapped("admin-actions"),
                vec![revoke.danger()],
                id.clone(),
            )
        } else {
            Cell::acts(Layout::Block, Vec::new(), String::new())
        };
        view = view.row(vec![
            Cell::code(row.name.clone()).attr("id", id).head(),
            Cell::text(row.role.clone()),
            Cell::of(row.created.as_ref().map(time).into_iter().collect()),
            Cell::of(vec![last_used]),
            actions,
        ]);
    }
    view
}
