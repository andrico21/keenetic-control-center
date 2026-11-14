//! The tables of the storage page: the media with the maintenance actions the role may
//! run, and the USB devices.

use kcc_i18n::{keys, locale::Locale};

use super::{
    storage::{Device, Medium},
    tables::{Viewer, headed, name_cell, said},
};
use crate::{
    page_kit::{gate::Controls, request::with_query},
    table::{
        acts::Act,
        cells::{Cell, Layout, Pill},
        head::Head,
        piece::Piece,
        rows::Table,
        view::TableView,
    },
};

/// The storage media of `table`, with the maintenance actions `controls` allow.
pub(super) fn media(
    table: &Table<Medium>,
    controls: &Controls,
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("id", keys::WEB_SYSTEM_STORAGE_ID),
        ("label", keys::WEB_SYSTEM_STORAGE_LABEL),
        ("filesystem", keys::WEB_SYSTEM_STORAGE_FILESYSTEM),
        ("size", keys::WEB_SYSTEM_STORAGE_SIZE),
        ("free", keys::WEB_SYSTEM_STORAGE_FREE),
    ];
    let allowed =
        ["partition_check", "eject", "partition_format"].map(|name| controls.allows(name));
    let actions = allowed.contains(&true);
    let empty = keys::WEB_SYSTEM_STORAGE_NO_MEDIA;
    let mut view = headed((table, empty), &columns, (actions, locale)).nested();
    for (index, row) in table.rows().iter().enumerate() {
        let id = format!("medium-{}", index.saturating_add(1));
        let owned = |value: Option<&str>| value.map(str::to_owned);
        let filesystem = row
            .filesystem()
            .map(|filesystem| Piece::span("mono", filesystem.to_owned()));
        let mut cells = vec![
            name_cell(row.id(), id.clone(), None),
            Cell::reported(locale, owned(row.label())),
            Cell::of(filesystem.into_iter().collect()),
            Cell::optional(owned(row.size_text())).class("numeric"),
            Cell::optional(owned(row.free_text())).class("numeric"),
        ];
        if actions {
            let url = |action: &str| {
                with_query(
                    &format!("/ui/r/{router}/system/storage/{action}"),
                    &[("media", row.id())],
                )
            };
            let [check, eject, format] = allowed;
            let mut acts = Vec::new();
            if check {
                let label = said(locale, keys::WEB_SYSTEM_STORAGE_CHECK);
                acts.push(Act::sends(label, url("check")));
            }
            if eject {
                let label = said(locale, keys::WEB_SYSTEM_STORAGE_EJECT);
                acts.push(Act::sends(label, url("eject")).danger());
            }
            if format {
                let act = Act::open(locale, keys::WEB_SYSTEM_STORAGE_FORMAT, url("format"));
                acts.push(act.danger());
            }
            cells.push(Cell::acts(Layout::Wrapped("admin-actions"), acts, id));
        }
        view = view.row(cells);
    }
    view
}

/// The USB devices, or a note in their place.
pub(super) fn usb(devices: &[Device], locale: Locale) -> TableView {
    let mut view = TableView::new("table").nested();
    if devices.is_empty() {
        return view.blank("panel__note", said(locale, keys::WEB_SYSTEM_STORAGE_NO_USB));
    }
    for key in [
        keys::WEB_SYSTEM_STORAGE_ID,
        keys::WEB_SYSTEM_STORAGE_DEVICE,
        keys::WEB_SYSTEM_SERVICES_STATE,
    ] {
        view = view.head(Head::plain(said(locale, key)));
    }
    for device in devices {
        let state = if device.connected() {
            Cell::pill(locale, Pill::On, keys::WEB_SYSTEM_STORAGE_CONNECTED)
        } else {
            Cell::pill(locale, Pill::Off, keys::WEB_SYSTEM_STORAGE_DISCONNECTED)
        };
        view = view.row(vec![
            Cell::of(vec![Piece::span("mono", device.id().to_owned())]).head(),
            Cell::text(device.name().to_owned()),
            state,
        ]);
    }
    view
}
