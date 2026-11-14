//! The views of the Wi-Fi tables: the radios and the access points with their actions,
//! and the connected devices, filtered, sorted and cut into pages.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    net_wifi_rows::{ApRow, RadioRow},
    net_wifi_stations::StationRow,
    page_kit::{gate::Controls, request::with_query},
    table::{
        acts::Act,
        cells::{Cell, Layout, Piece},
        rows::Table,
        view::{Head, TableView},
    },
};

/// The table class of every Wi-Fi table.
const CLASS: &str = "table net-table";

/// The message `key` in `locale`.
fn said(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
}

/// The settings dialog of the radio or access point `name` on `router`.
fn settings_url(router: &str, name: &str) -> String {
    with_query(&format!("/ui/r/{router}/wifi/settings"), &[("name", name)])
}

/// `value`, or "not reported", in `locale`.
fn reported(locale: Locale, value: Option<&str>) -> Cell {
    Cell::reported(locale, value.map(str::to_owned))
}

/// The radios on `router` with Settings.
pub(crate) fn radios_view(router: &str, radios: &[RadioRow], locale: Locale) -> TableView {
    let mut view = TableView::new(CLASS).nested();
    for key in [
        keys::WEB_WIFI_RADIO,
        keys::WEB_WIFI_BAND,
        keys::WEB_WIFI_CHANNEL,
        keys::WEB_WIFI_WIDTH,
        keys::WEB_WIFI_POWER,
        keys::WEB_WIFI_COUNTRY,
    ] {
        view = view.head(Head::plain(said(locale, key)));
    }
    view = view.head(Head::hidden(said(locale, keys::WEB_ADMIN_ACTIONS)));
    for (index, radio) in radios.iter().enumerate() {
        let id = format!("radio-{}", index.saturating_add(1));
        let settings = Act::opens(
            said(locale, keys::WEB_INTERNET_SETTINGS),
            settings_url(router, radio.id()),
        );
        view = view.row(vec![
            Cell::code(radio.id().to_owned())
                .attr("id", id.clone())
                .head(),
            reported(locale, radio.band()),
            reported(locale, radio.channel()).class("numeric"),
            reported(locale, radio.width()),
            reported(locale, radio.power()).class("numeric"),
            reported(locale, radio.country()),
            Cell::acts(Layout::Inline, vec![settings], id),
        ]);
    }
    view
}

/// The access points on `router` with Settings and, where `controls` allow it, Enable or
/// Disable.
pub(crate) fn points_view(
    router: &str,
    points: &[ApRow],
    (controls, locale): (&Controls, Locale),
) -> TableView {
    let mut view = TableView::new(CLASS).nested();
    for key in [
        keys::DOMAINS_WIFI_SSID,
        keys::WEB_WIFI_SECURITY,
        keys::WEB_WIFI_PSK,
        keys::WEB_WIFI_HIDDEN,
        keys::WEB_WIFI_STATE,
        keys::WEB_WIFI_SCHEDULE,
        keys::WEB_WIFI_SEGMENT,
    ] {
        view = view.head(Head::plain(said(locale, key)));
    }
    view = view.head(Head::hidden(said(locale, keys::WEB_ADMIN_ACTIONS)));
    for (index, point) in points.iter().enumerate() {
        let id = format!("point-{}", index.saturating_add(1));
        let ssid = point.ssid().map_or_else(
            || Piece::span("muted", said(locale, keys::WEB_KIT_NOT_REPORTED)),
            |text| Piece::text(text.to_owned()),
        );
        let name = Piece::span("net-table__note mono", point.id().to_owned());
        let segment = point.segment().map_or_else(
            || Cell::missing(locale, keys::WEB_KIT_NOT_REPORTED),
            |text| Cell::of(vec![Piece::span("mono", text.to_owned())]),
        );
        let mut acts = vec![Act::opens(
            said(locale, keys::WEB_INTERNET_SETTINGS),
            settings_url(router, point.id()),
        )];
        if controls.allows("up") {
            let enable = point.enabled() == Some(false);
            let label = if enable {
                keys::WEB_NETWORK_ENABLE
            } else {
                keys::WEB_NETWORK_DISABLE
            };
            let href = with_query(
                &format!("/ui/r/{router}/wifi/toggle"),
                &[
                    ("name", point.id()),
                    ("setting", "enabled"),
                    ("value", if enable { "yes" } else { "no" }),
                ],
            );
            acts.push(Act::sends(said(locale, label), href));
        }
        view = view.row(vec![
            Cell::of(vec![ssid, name]).attr("id", id.clone()).head(),
            reported(locale, point.security()),
            Cell::text(point.password_text(locale)),
            Cell::reported(locale, point.hidden_text(locale)),
            Cell::reported(locale, point.state_text(locale)),
            reported(locale, point.schedule()),
            segment,
            Cell::acts(Layout::Wrapped("admin-actions"), acts, id),
        ]);
    }
    view
}

/// The shown page of connected devices, strongest signal first by default.
pub(crate) fn stations_view(table: &Table<StationRow>, locale: Locale) -> TableView {
    let empty = (
        locale,
        keys::WEB_WIFI_STATIONS_FILTER,
        keys::WEB_WIFI_STATIONS_NONE,
    );
    let mut view = TableView::counted(CLASS, table, empty).nested();
    for (column, key) in [
        ("mac", keys::WEB_NETWORK_MAC),
        ("access-point", keys::WEB_WIFI_ACCESS_POINT),
        ("ssid", keys::DOMAINS_WIFI_SSID),
        ("signal", keys::WEB_WIFI_SIGNAL),
        ("rx", keys::WEB_WIFI_RX_RATE),
        ("tx", keys::WEB_WIFI_TX_RATE),
    ] {
        view = view.head(Head::sorted(said(locale, key), table.header(column)));
    }
    for station in table.rows() {
        view = view.row(vec![
            Cell::code(station.mac().to_owned()).head(),
            Cell::optional(station.interface().map(str::to_owned)).class("mono"),
            Cell::optional(station.ssid().map(str::to_owned)),
            Cell::reported(locale, station.signal_text(locale)).class("numeric"),
            Cell::reported(locale, station.rx_text(locale)).class("numeric"),
            Cell::reported(locale, station.tx_text(locale)).class("numeric"),
        ]);
    }
    view
}
