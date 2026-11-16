//! The accounts table: name, role and state flags, and the changes the signed-in user may
//! make: role, enable or disable, unlock, delete.

use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::UserRow;
use crate::table::{
    acts::Act,
    cells::{Cell, Layout},
    head::Head,
    piece::{Line, Piece},
    view::TableView,
};

/// The table of `rows` in `locale`.
pub(super) fn accounts(rows: &[UserRow], locale: Locale) -> TableView {
    let mut view = TableView::new("table");
    for key in [
        keys::WEB_ADMIN_USER_NAME,
        keys::WEB_ADMIN_USER_ROLE,
        keys::WEB_ADMIN_USER_STATE,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    for (index, row) in rows.iter().enumerate() {
        let id = format!("user-{}", index.saturating_add(1));
        let mut name = vec![Piece::text(row.username.clone())];
        if row.is_self() {
            name.push(Piece::text(" ".to_owned()));
            name.push(Piece::span(
                "muted",
                tr(locale, keys::WEB_ADMIN_USER_YOU, None),
            ));
        }
        let actions = if row.manageable() {
            Cell::acts(
                Layout::Wrapped("admin-actions"),
                acts(row, locale),
                id.clone(),
            )
        } else {
            Cell::acts(Layout::Block, Vec::new(), String::new())
        };
        view = view.row(vec![
            Cell::of(name).class("mono").attr("id", id).head(),
            Cell::text(row.role.clone()),
            Cell::stack(vec![Line::Open(flags(row, locale))]),
            actions,
        ]);
    }
    view
}

/// The state of `row`: active or disabled, then its lockout and password flags.
fn flags(row: &UserRow, locale: Locale) -> Piece {
    let state = if row.disabled {
        Piece::span(
            "status",
            tr(locale, keys::WEB_ADMIN_USER_DISABLED_STATE, None),
        )
        .attr("data-status", "unknown".to_owned())
    } else {
        Piece::span("status", tr(locale, keys::WEB_ADMIN_USER_ACTIVE, None))
            .attr("data-status", "online".to_owned())
    };
    row.flags.iter().fold(
        Piece::span("admin-flags", String::new()).with(state),
        |flags, flag| {
            flags.with(
                Piece::span("flag", tr(locale, flag.label, None))
                    .attr("data-tone", flag.tone.to_owned()),
            )
        },
    )
}

/// The changes the signed-in user may make to `row`.
fn acts(row: &UserRow, locale: Locale) -> Vec<Act> {
    let named = |path: &str| (path.to_owned(), vec![("name", row.username.clone())]);
    let mut acts = vec![Act::open(
        locale,
        keys::WEB_ADMIN_USER_CHANGE_ROLE,
        row.role_url.clone(),
    )];
    acts.push(if row.disabled {
        Act::quiet(
            locale,
            keys::WEB_ADMIN_USER_ENABLE,
            named("/ui/admin/users/enable"),
        )
    } else {
        Act::quiet(
            locale,
            keys::WEB_ADMIN_USER_DISABLE,
            named("/ui/admin/users/disable"),
        )
    });
    if row.unlock {
        acts.push(Act::quiet(
            locale,
            keys::WEB_ADMIN_USER_UNLOCK,
            named("/ui/admin/users/unlock"),
        ));
    }
    acts.push(Act::open(locale, keys::COMMON_DELETE, row.delete_url.clone()).danger());
    acts
}
