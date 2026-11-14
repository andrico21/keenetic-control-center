//! The roles table: name, permissions, scope and holders, and Edit and Delete where the
//! signed-in user may.

use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::RoleRow;
use crate::table::{
    acts::Act,
    cells::{Cell, Layout},
    head::Head,
    piece::Piece,
    view::TableView,
};

/// The table of `rows` in `locale`.
pub(super) fn roles(rows: &[RoleRow], locale: Locale) -> TableView {
    let mut view = TableView::new("table");
    for key in [
        keys::WEB_ADMIN_ROLE_NAME,
        keys::WEB_ADMIN_ROLE_PERMISSIONS,
        keys::WEB_ADMIN_ROLE_SCOPE,
        keys::WEB_ADMIN_ROLE_HOLDERS,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    for (index, row) in rows.iter().enumerate() {
        let id = format!("role-{}", index.saturating_add(1));
        let mut name = vec![Piece::text(row.label.clone())];
        if row.built_in {
            let built_in = tr(locale, keys::WEB_ADMIN_ROLE_BUILT_IN, None);
            name.push(Piece::text(" ".to_owned()));
            name.push(Piece::span("flag", built_in).attr("data-tone", "info".to_owned()));
        }
        let actions = if row.editable {
            let mut acts = vec![Act::open(locale, keys::COMMON_EDIT, row.edit_url.clone())];
            if row.deletable {
                acts.push(Act::open(locale, keys::COMMON_DELETE, row.delete_url.clone()).danger());
            }
            Cell::acts(Layout::Wrapped("admin-actions"), acts, id.clone())
        } else {
            Cell::acts(Layout::Block, Vec::new(), String::new())
        };
        view = view.row(vec![
            Cell::of(name).attr("id", id).head(),
            Cell::text(row.permissions.clone()),
            Cell::code(row.scope.clone()),
            Cell::text(row.holders.to_string()).class("numeric"),
            actions,
        ]);
    }
    view
}
