//! The tables of the system pages: services, schedules, components and router accounts,
//! each row with the actions the role may use.

use kcc_domain::components::QueueAction;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{components::Component, schedules::Schedule, services::Service, users::Account};
use crate::{
    page_kit::request::with_query,
    table::{
        acts::Act,
        cells::{Cell, Layout, Pill},
        head::Head,
        piece::Piece,
        rows::{Row, Table},
        view::TableView,
    },
};

/// Where a table is and who reads it: the router and the locale.
pub(super) type Viewer<'call> = (&'call str, Locale);

/// The message `key` in `locale`.
pub(super) fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// The filtered view of `table` with the sorted `columns`, a note in class `panel__note`
/// saying `empty` in its place, and a hidden head over the actions when `actions`.
pub(super) fn headed<R>(
    (table, empty): (&Table<R>, MessageKey),
    columns: &[(&'static str, MessageKey)],
    (actions, locale): (bool, Locale),
) -> TableView
where
    R: Row,
{
    let mut view = TableView::filtered("table", table, (locale, empty)).noted("panel__note");
    for (column, key) in columns {
        view = view.head(Head::sorted(said(locale, *key), table.header(column)));
    }
    if actions {
        view = view.head(Head::hidden(said(locale, keys::WEB_SYSTEM_ACTIONS)));
    }
    view
}

/// The row header of `name`, element id `id`, with a flag after it when `flag` is set.
pub(super) fn name_cell(name: &str, id: String, flag: Option<String>) -> Cell {
    let mut pieces = vec![Piece::span("mono", name.to_owned())];
    if let Some(text) = flag {
        pieces.push(Piece::text(" ".to_owned()));
        pieces.push(Piece::span("flag", text).attr("data-tone", "info".to_owned()));
    }
    Cell::of(pieces).attr("id", id).head()
}

/// The services of `table`; Turn on or off where the role may switch ordinary or
/// management services (`plain`, `management`).
pub(super) fn services(
    table: &Table<Service>,
    (plain, management): (bool, bool),
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("name", keys::WEB_SYSTEM_SERVICES_NAME),
        ("state", keys::WEB_SYSTEM_SERVICES_STATE),
    ];
    let actions = plain || management;
    let mut view = headed(
        (table, keys::WEB_KIT_TABLE_EMPTY),
        &columns,
        (actions, locale),
    );
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("service-{}", index.saturating_add(1));
        let flag = row
            .management()
            .then(|| said(locale, keys::WEB_SYSTEM_SERVICES_MANAGEMENT));
        let state = if row.on() {
            Cell::pill(locale, Pill::On, keys::WEB_SYSTEM_SERVICES_ON)
        } else {
            Cell::pill(locale, Pill::Off, keys::WEB_SYSTEM_SERVICES_OFF)
        };
        let mut cells = vec![name_cell(row.name(), id.clone(), flag), state];
        if actions {
            let switchable = if row.management() { management } else { plain };
            let mut acts = Vec::new();
            if switchable {
                let (wanted, label) = if row.on() {
                    ("false", keys::WEB_SYSTEM_SERVICES_TURN_OFF)
                } else {
                    ("true", keys::WEB_SYSTEM_SERVICES_TURN_ON)
                };
                let href = with_query(
                    &format!("/ui/r/{router}/system/services/toggle"),
                    &[("name", row.name()), ("on", wanted)],
                );
                acts.push(Act::sends(said(locale, label), href));
            }
            cells.push(Cell::acts(Layout::Block, acts, id));
        }
        view = view.row(cells);
    }
    view
}

/// The schedules of `table`, with Add action where the role may (`act`).
pub(super) fn schedules(
    table: &Table<Schedule>,
    act: bool,
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("name", keys::WEB_SYSTEM_SCHEDULES_NAME),
        ("description", keys::WEB_SYSTEM_SCHEDULES_DESCRIPTION),
        ("state", keys::WEB_SYSTEM_SERVICES_STATE),
    ];
    let empty = keys::WEB_SYSTEM_SCHEDULES_EMPTY;
    let mut view = headed((table, empty), &columns, (act, locale));
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("schedule-{}", index.saturating_add(1));
        let state = match row.active() {
            Some(true) => Cell::pill(locale, Pill::On, keys::WEB_SYSTEM_SCHEDULES_ACTIVE),
            Some(false) => Cell::pill(locale, Pill::Off, keys::WEB_SYSTEM_SCHEDULES_INACTIVE),
            None => Cell::missing(locale, keys::WEB_KIT_NOT_REPORTED),
        };
        let mut cells = vec![
            name_cell(row.name(), id.clone(), None),
            Cell::reported(locale, row.description().map(str::to_owned)),
            state,
        ];
        if act {
            let href = with_query(
                &format!("/ui/r/{router}/system/schedules/action"),
                &[("name", row.name())],
            );
            let add = Act::open(locale, keys::WEB_SYSTEM_SCHEDULES_ADD_ACTION, href);
            cells.push(Cell::acts(Layout::Inline, vec![add], id));
        }
        view = view.row(cells);
    }
    view
}

/// The components of `table`, with Install or Remove where the role may queue (`queue`).
pub(super) fn components(
    table: &Table<Component>,
    queue: bool,
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("name", keys::WEB_SYSTEM_COMPONENTS_NAME),
        ("state", keys::WEB_SYSTEM_SERVICES_STATE),
    ];
    let mut view = headed(
        (table, keys::WEB_KIT_TABLE_EMPTY),
        &columns,
        (queue, locale),
    )
    .nested();
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("component-{}", index.saturating_add(1));
        let label = said(locale, row.label());
        let state = if row.queued() {
            Cell::of(vec![Piece::span("flag", label)])
        } else {
            Cell::text(label)
        };
        let mut cells = vec![name_cell(row.name(), id.clone(), None), state];
        if queue {
            let acts = row.action().map(|action| {
                let (word, key) = match action {
                    QueueAction::Install => ("install", keys::WEB_SYSTEM_COMPONENTS_INSTALL),
                    QueueAction::Remove | _ => ("remove", keys::WEB_SYSTEM_COMPONENTS_REMOVE),
                };
                let href = with_query(
                    &format!("/ui/r/{router}/system/components/queue"),
                    &[("name", row.name()), ("action", word)],
                );
                Act::sends(said(locale, key), href)
            });
            cells.push(Cell::acts(Layout::Block, acts.into_iter().collect(), id));
        }
        view = view.row(cells);
    }
    view
}

/// The router accounts of `table`, with the actions the role may use: edit tags, set
/// the password, delete.
pub(super) fn accounts(
    table: &Table<Account>,
    (tags, password, delete): (bool, bool, bool),
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("name", keys::WEB_SYSTEM_USERS_NAME),
        ("tags", keys::WEB_SYSTEM_USERS_TAGS),
    ];
    let actions = tags || password || delete;
    let empty = keys::WEB_SYSTEM_USERS_EMPTY;
    let mut view = headed((table, empty), &columns, (actions, locale));
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("user-{}", index.saturating_add(1));
        let flag = row
            .signs_in()
            .then(|| said(locale, keys::WEB_SYSTEM_USERS_KCC_LOGIN));
        let listed = if row.untagged() {
            Piece::span("muted", said(locale, keys::WEB_SYSTEM_USERS_NO_TAGS))
        } else {
            Piece::span("mono", row.tag_list())
        };
        let mut cells = vec![
            name_cell(row.name(), id.clone(), flag),
            Cell::of(vec![listed]),
        ];
        if actions {
            let url = |dialog: &str| {
                with_query(
                    &format!("/ui/r/{router}/system/users/{dialog}"),
                    &[("name", row.name())],
                )
            };
            let own = !row.signs_in();
            let acts = [
                (tags, keys::WEB_SYSTEM_USERS_EDIT_TAGS, "tags"),
                (password && own, keys::WEB_SECRET_SET_PASSWORD, "password"),
                (delete && own, keys::COMMON_DELETE, "delete"),
            ]
            .into_iter()
            .filter(|(shown, ..)| *shown)
            .map(|(_, label, dialog)| {
                let act = Act::open(locale, label, url(dialog));
                if dialog == "delete" {
                    act.danger()
                } else {
                    act
                }
            })
            .collect();
            cells.push(Cell::acts(Layout::Wrapped("admin-actions"), acts, id));
        }
        view = view.row(cells);
    }
    view
}
