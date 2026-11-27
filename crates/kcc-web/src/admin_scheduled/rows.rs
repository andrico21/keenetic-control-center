//! The schedules table: what each schedule does and when, its state, next and last run,
//! and the actions on it.

use kcc_app::schedules::{model::ScheduleState, time::format_local};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use url::form_urlencoded;

use super::{Listed, text};
use crate::table::{
    acts::Act,
    cells::{Cell, Layout},
    head::Head,
    piece::Piece,
    view::TableView,
};

/// The table of `listed` in `locale` at `now`; the actions that need a running scheduler
/// show only when `running`.
pub(super) fn table(listed: &[Listed], locale: Locale, now: i64, running: bool) -> TableView {
    let mut view = TableView::new("table");
    if listed.is_empty() {
        return view.blank(
            "page__text",
            tr(locale, keys::WEB_ADMIN_SCHEDULED_EMPTY, None),
        );
    }
    for key in [
        keys::WEB_ADMIN_SCHEDULED_NAME,
        keys::WEB_ADMIN_SCHEDULED_ROUTER,
        keys::WEB_ADMIN_SCHEDULED_DAYS,
        keys::WEB_ADMIN_SCHEDULED_TIME,
        keys::WEB_ADMIN_SCHEDULED_ACTION,
        keys::WEB_ADMIN_SCHEDULED_OWNER,
        keys::WEB_ADMIN_SCHEDULED_STATE,
        keys::WEB_ADMIN_SCHEDULED_NEXT,
        keys::WEB_ADMIN_SCHEDULED_LAST,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(locale, keys::WEB_ADMIN_ACTIONS, None)));
    for (index, entry) in listed.iter().enumerate() {
        let row = format!("scheduled-{}", index.saturating_add(1));
        view = view.row(row_cells(entry, locale, (now, running), row));
    }
    view
}

/// The cells of one schedule's row, whose header has the element id `row`.
fn row_cells(
    entry: &Listed,
    locale: Locale,
    (now, running): (i64, bool),
    row: String,
) -> Vec<Cell> {
    let schedule = &entry.schedule;
    let (tone, state) = text::state(schedule);
    let active = schedule.state == ScheduleState::Active;
    let next = active
        .then(|| schedule.when.next_slot_unix(now))
        .flatten()
        .map(|slot| format_local(slot, schedule.when.zone()));
    let last = entry.last.as_ref().map_or_else(
        || Cell::missing(locale, keys::WEB_ADMIN_SCHEDULED_LAST_NONE),
        |run| {
            let (run_tone, words) = text::last_run(run, schedule, locale);
            flag(run_tone, words)
        },
    );
    vec![
        Cell::text(schedule.name.as_str().to_owned())
            .attr("id", row.clone())
            .head(),
        Cell::text(entry.router_name.clone()),
        Cell::text(text::days(schedule, locale)),
        Cell::text(text::time(schedule)),
        Cell::text(text::summary(&schedule.action, locale)),
        Cell::code(schedule.owner.to_string()),
        flag(tone, tr(locale, state, None)),
        next.map_or_else(
            || Cell::missing(locale, keys::WEB_ADMIN_SCHEDULED_NEXT_NONE),
            Cell::text,
        ),
        last,
        Cell::acts(
            Layout::Wrapped("admin-actions"),
            acts(&schedule.id, locale, active, running),
            row,
        ),
    ]
}

/// A state reading `words` in a flag of `tone`: the words carry it, the tone only adds to
/// them.
fn flag(tone: &'static str, words: String) -> Cell {
    Cell::of(vec![
        Piece::span("flag", words).attr("data-tone", tone.to_owned()),
    ])
}

/// The actions on schedule `id`: edit, pause or resume, run now and delete; without a
/// running scheduler, pause and delete only.
fn acts(id: &str, locale: Locale, active: bool, running: bool) -> Vec<Act> {
    let posted = |path: &str| (path.to_owned(), vec![("id", id.to_owned())]);
    let dialog = |path: &str| named_id(path, id);
    let mut acts = Vec::new();
    if running {
        acts.push(Act::open(
            locale,
            keys::WEB_ADMIN_SCHEDULED_EDIT,
            dialog("/ui/admin/scheduled/edit"),
        ));
    }
    match (active, running) {
        (true, _) => acts.push(Act::post(
            locale,
            keys::WEB_ADMIN_SCHEDULED_PAUSE,
            posted("/ui/admin/scheduled/pause"),
        )),
        (false, true) => acts.push(Act::post(
            locale,
            keys::WEB_ADMIN_SCHEDULED_RESUME,
            posted("/ui/admin/scheduled/resume"),
        )),
        (false, false) => {}
    }
    if running {
        acts.push(Act::open(
            locale,
            keys::WEB_ADMIN_SCHEDULED_RUN,
            dialog("/ui/admin/scheduled/run-now"),
        ));
    }
    acts.push(
        Act::open(
            locale,
            keys::COMMON_DELETE,
            dialog("/ui/admin/scheduled/delete"),
        )
        .danger(),
    );
    acts
}

/// `base?id=<id>`, with `id` URL-encoded.
pub(super) fn named_id(base: &str, id: &str) -> String {
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("id", id)
        .finish();
    format!("{base}?{query}")
}
