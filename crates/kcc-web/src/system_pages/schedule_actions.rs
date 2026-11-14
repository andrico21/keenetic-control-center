//! The add-action dialog of the schedules page and its change.
//!
//! The router's CLI takes an action as start or stop, a minute, an hour and a day-of-week
//! bit field (Monday the lowest bit, Sunday the highest); the time and the days are
//! checked here before anything is sent.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_catalog::Risk;
use kcc_domain::schedules::{self, ActionTime, ScheduleAction};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    schedules::{Viewer, read},
    shared::{answer, value, values},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::Change,
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        request::{missing, shown_query},
        respond::{self, Answer},
    },
};

/// Adding an action to a schedule, audited as `web.schedule_action`.
const ACTION: Operation = Operation::write(&schedules::DESCRIPTOR, "action", "web.schedule_action");

/// The days of the week, Monday first, with their labels; a day's bit is its index.
const DAYS: [(&str, MessageKey); 7] = [
    ("mon", keys::WEB_SYSTEM_SCHEDULES_MONDAY),
    ("tue", keys::WEB_SYSTEM_SCHEDULES_TUESDAY),
    ("wed", keys::WEB_SYSTEM_SCHEDULES_WEDNESDAY),
    ("thu", keys::WEB_SYSTEM_SCHEDULES_THURSDAY),
    ("fri", keys::WEB_SYSTEM_SCHEDULES_FRIDAY),
    ("sat", keys::WEB_SYSTEM_SCHEDULES_SATURDAY),
    ("sun", keys::WEB_SYSTEM_SCHEDULES_SUNDAY),
];

/// The add-action dialog.
#[derive(Template)]
#[template(path = "partials/system_action_dialog.html")]
struct ActionDialog {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Localized title naming the schedule.
    title: String,
    /// The schedule.
    schedule: String,
    /// Whether the action starts (else stops) what the schedule controls.
    start: bool,
    /// The time as typed.
    time_value: String,
    /// Localized error under the time; empty when none.
    time_error: String,
    /// The days and whether each is checked.
    days: Vec<(&'static str, MessageKey, bool)>,
    /// Localized error under the days; empty when none.
    days_error: String,
}

localized!(ActionDialog);

/// The minute and hour of `time`, written `HH:MM`.
fn clock(time: &str) -> Option<(u8, u8)> {
    let (hours, minutes) = time.split_once(':')?;
    let hour: u8 = hours.parse().ok().filter(|value| *value < 24)?;
    let minute: u8 = minutes.parse().ok().filter(|value| *value < 60)?;
    Some((minute, hour))
}

/// The day-of-week bit field of the checked `days`, or `None` when none is checked.
fn weekdays(days: &[&str]) -> Option<u8> {
    let field = DAYS
        .iter()
        .zip(0_u32..)
        .filter(|((day, _), _)| days.contains(day))
        .fold(0_u8, |field, (_, bit)| {
            field | 1_u8.checked_shl(bit).unwrap_or(0)
        });
    (field != 0).then_some(field)
}

/// The add-action dialog of `schedule` on `router`, starting with nothing checked.
fn action_dialog(router: &str, locale: Locale, schedule: &str) -> ActionDialog {
    let mut args = FluentArgs::new();
    args.set("name", schedule.to_owned());
    ActionDialog {
        shell: fragment_shell(locale),
        router: router.to_owned(),
        title: tr(locale, keys::WEB_SYSTEM_SCHEDULES_ACTION_TITLE, Some(&args)),
        schedule: schedule.to_owned(),
        start: true,
        time_value: String::new(),
        time_error: String::new(),
        days: DAYS
            .iter()
            .map(|(day, label)| (*day, *label, false))
            .collect(),
        days_error: String::new(),
    }
}

/// `GET /ui/r/{router}/system/schedules/action?name=`: the add-action dialog.
///
/// # Errors
///
/// Answers 404 for an unknown schedule, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn action_form(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = ACTION.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let name = value(&query, "name").unwrap_or_default();
    let known = read(&domain).await.unwrap_or_default();
    if !known.iter().any(|schedule| schedule.name() == name) {
        return Err(missing());
    }
    Ok(errors::render(&action_dialog(
        &router,
        action.locale(),
        name,
    )))
}

/// `POST /ui/r/{router}/system/schedules/action`: adds a timed action to a schedule.
///
/// # Errors
///
/// Answers 404 for an unknown schedule, the dialog with its field errors (422), and what
/// the kit answers when the router or the permission is missing.
pub(crate) async fn add_action(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = ACTION.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    if !read(&domain)
        .await
        .unwrap_or_default()
        .iter()
        .any(|schedule| schedule.name() == name)
    {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let time = value(&pairs, "time").unwrap_or_default();
    let checked = values(&pairs, "day");
    let start = value(&pairs, "action") != Some("stop");
    let mut dialog = action_dialog(&router, locale, &name);
    dialog.start = start;
    time.clone_into(&mut dialog.time_value);
    for (day, _, checked_day) in &mut dialog.days {
        *checked_day = checked.contains(day);
    }
    let when = clock(time);
    let days = weekdays(&checked);
    if when.is_none() {
        dialog.time_error = tr(locale, keys::WEB_SYSTEM_SCHEDULES_TIME_ERROR, None);
    }
    if days.is_none() {
        dialog.days_error = tr(locale, keys::WEB_SYSTEM_SCHEDULES_DAYS_ERROR, None);
    }
    let (Some((minute, hour)), Some(field)) = (when, days) else {
        action.abandon("validation_failed").await;
        return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
    };
    let kind = if start {
        ScheduleAction::Start
    } else {
        ScheduleAction::Stop
    };
    let planned =
        schedules::plan_action(&domain, &name, ActionTime::new(kind, minute, hour, field))
            .and_then(|operation| schedules::change_request(&operation));
    let request = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            plan_failure(Family::Changes, locale, &error)
                .message()
                .clone_into(&mut dialog.time_error);
            return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
        }
    };
    let outcome = action.run(Risk::Write, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&domain)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, locale))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{clock, weekdays};

    #[test]
    fn times_and_days_are_checked_before_anything_is_sent() {
        assert_eq!(clock("08:30"), Some((30, 8)), "minute, hour");
        assert_eq!(clock("24:00"), None, "hour");
        assert_eq!(clock("8"), None, "no minute");
        assert_eq!(
            weekdays(&["mon", "sun"]),
            Some(0b100_0001),
            "Monday and Sunday"
        );
        assert_eq!(weekdays(&[]), None, "no day");
    }
}
