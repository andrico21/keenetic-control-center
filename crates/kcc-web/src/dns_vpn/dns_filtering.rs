//! The DNS filtering tab: the engine and interception, the profiles, then the profile
//! assignments.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{
    dns_forms::engine_label,
    dns_read::DnsState,
    dns_tabs::{dialog, value},
    flow::Viewer,
    listing::{Line, Listing, table_view},
    region::{Panel, Region},
};
use crate::table::{Direction, Sort, acts::Act, cells::Cell, rows::Table};

/// The profile assignments table.
#[derive(Debug, Clone, Copy)]
struct Assignments;

impl Listing for Assignments {
    const COLUMNS: &'static [&'static str] = &["target", "kind", "profile"];
    const LABELS: &'static [MessageKey] = &[
        keys::WEB_DNS_TARGET,
        keys::WEB_DNS_TARGET_KIND,
        keys::WEB_DNS_PROFILE,
    ];
    const DEFAULT: Sort = Sort::new("target", Direction::Ascending);

    fn name(&self) -> MessageKey {
        keys::WEB_DNS_ASSIGNMENTS
    }

    fn empty(&self) -> MessageKey {
        keys::WEB_DNS_ASSIGNMENTS_EMPTY
    }
}

/// The filtering tab: the engine and interception, the profiles, then the assignments.
pub(crate) fn filtering(state: &DnsState, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let engine = state
        .engine()
        .map(|name| tr(locale, engine_label(&name), None));
    let intercept = state.intercept();
    let shown = intercept.map(|on| {
        let key = if on {
            keys::WEB_DNS_ON
        } else {
            keys::WEB_DNS_OFF
        };
        tr(locale, key, None)
    });
    let edit = viewer
        .allows("filter_engine")
        .then(|| viewer.href("dns/form/engine"));
    let mut settings = Panel::new(locale, "dns-filter", keys::WEB_DNS_FILTER_SETTINGS)
        .row((locale, keys::WEB_DNS_ENGINE), engine, edit)
        .row((locale, keys::WEB_DNS_INTERCEPT), shown, None);
    if viewer.allows("intercept") {
        let (label, next) = if intercept == Some(true) {
            (keys::WEB_DNS_INTERCEPT_OFF, "off")
        } else {
            (keys::WEB_DNS_INTERCEPT_ON, "on")
        };
        let fields = vec![("enabled", next.to_owned())];
        settings = settings.act(Act::post(
            locale,
            label,
            (viewer.href("dns/intercept"), fields),
        ));
    }
    let profiles = state.profiles();
    let mut listed = Panel::new(locale, "dns-profiles", keys::WEB_DNS_PROFILES).items(
        profiles
            .iter()
            .map(|entry| entry.name().to_owned())
            .collect(),
    );
    if profiles.is_empty() {
        listed = listed.note(tr(locale, keys::WEB_DNS_PROFILES_EMPTY, None));
    }
    let assigns = viewer.allows("filter_profile");
    if assigns {
        let href = viewer.href("dns/form/profile");
        listed = listed.act(Act::open(locale, keys::WEB_DNS_PROFILE_ADD, href));
    }
    let lines = state
        .assignments()
        .iter()
        .map(|(host, entry)| {
            let kind = if *host {
                keys::WEB_DNS_TARGET_HOST
            } else {
                keys::WEB_DNS_TARGET_INTERFACE
            };
            Line::new(vec![
                Cell::code(entry.name().to_owned()),
                Cell::word(locale, kind),
                value(locale, entry, 0),
            ])
        })
        .collect();
    let table = Table::new(lines, viewer.query(), viewer.href("dns/filtering"));
    let actions = (assigns && !profiles.is_empty())
        .then(|| dialog(viewer, keys::WEB_DNS_ASSIGN_TITLE, "assign"))
        .into_iter()
        .collect();
    let region = Region::new(locale)
        .panel(settings)
        .panel(listed)
        .table(table_view(&Assignments, &table, locale));
    (region, actions)
}
