//! The tables of the storage page: the media with Eject and Prepare for Entware where the
//! role may run them, and the USB devices.

use kcc_i18n::{keys, locale::Locale};

use super::{
    storage::{Device, Medium},
    tables::{Viewer, headed, name_cell, said},
};
use crate::{
    page_kit::request::with_query,
    table::{
        acts::Act,
        cells::{Cell, Layout, Pill},
        head::Head,
        piece::Piece,
        rows::Table,
        view::TableView,
    },
};

/// The storage media of `table`, with Eject and, for a medium the router can initialize
/// with ext4, Prepare for Entware, each where the role may run it (`eject`, `prepare`).
pub(super) fn media(
    table: &Table<Medium>,
    (eject, prepare): (bool, bool),
    (router, locale): Viewer<'_>,
) -> TableView {
    let columns = [
        ("id", keys::WEB_SYSTEM_STORAGE_ID),
        ("label", keys::WEB_SYSTEM_STORAGE_LABEL),
        ("filesystem", keys::WEB_SYSTEM_STORAGE_FILESYSTEM),
        ("size", keys::WEB_SYSTEM_STORAGE_SIZE),
        ("free", keys::WEB_SYSTEM_STORAGE_FREE),
    ];
    let actions = eject || prepare;
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
            let url = |slug: &str| {
                with_query(
                    &format!("/ui/r/{router}/system/storage/{slug}"),
                    &[("media", row.id())],
                )
            };
            let mut acts = Vec::new();
            if eject {
                let label = said(locale, keys::WEB_SYSTEM_STORAGE_EJECT);
                acts.push(Act::sends(label, url("eject")).danger());
            }
            if prepare && row.initializable() {
                let label = said(locale, keys::WEB_SYSTEM_ENTWARE_PREPARE);
                acts.push(Act::sends(label, url("initialize")).danger());
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
