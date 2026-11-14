//! The add-action dialog of the schedules page and its change.
//!
//! The router's CLI takes an action as start or stop, a minute, an hour and a day-of-week
//! bit field (Monday the lowest bit, Sunday the highest); the time and the days are
//! checked here before anything is sent.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::schedules::{self, ActionTime, ScheduleAction};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    schedules::{Viewer, read},
    shared::{value, values},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        form::{Choice, FormDialog, Input},
        request::{Params, missing, shown_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
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

/// The add-action dialog of `schedule` on `router`, showing `(start, time, days)` as
/// chosen; a change the domain could not plan shows under the time.
fn action_dialog(
    (router, locale): (&str, Locale),
    schedule: &str,
    (start, time, days): (bool, &str, &[&str]),
) -> FormDialog {
    let mut args = FluentArgs::new();
    args.set("name", schedule.to_owned());
    let actions = vec![
        Choice::word(locale, "start", keys::WEB_SYSTEM_SCHEDULES_START),
        Choice::word(locale, "stop", keys::WEB_SYSTEM_SCHEDULES_STOP),
    ];
    let checks = DAYS
        .iter()
        .map(|(day, label)| Choice::word(locale, day, *label).checked(days.contains(day)))
        .collect();
    FormDialog::titled(
        locale,
        tr(locale, keys::WEB_SYSTEM_SCHEDULES_ACTION_TITLE, Some(&args)),
        format!("/ui/r/{router}/system/schedules/action"),
    )
    .ids("action")
    .submit(keys::WEB_SYSTEM_SCHEDULES_ADD_ACTION)
    .refusing_at("time")
    .with_input(Input::hidden("name", schedule.to_owned()))
    .with_input(
        Input::text("action", keys::WEB_SYSTEM_SCHEDULES_ACTION)
            .radio(actions)
            .value(if start { "start" } else { "stop" }.to_owned()),
    )
    .with_input(
        Input::field("time", keys::WEB_SYSTEM_SCHEDULES_TIME, time.to_owned()).typed("time"),
    )
    .with_input(
        Input::text("day", keys::WEB_SYSTEM_SCHEDULES_DAYS)
            .checks(checks)
            .id("action-days"),
    )
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
    Ok(action_dialog((&router, action.locale()), name, (true, "", &[])).show())
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
    let dialog = action_dialog((&router, locale), &name, (start, time, &checked));
    let kind = if start {
        ScheduleAction::Start
    } else {
        ScheduleAction::Stop
    };
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &Params::default(), dialog)
        .submit(
            |_params| match (clock(time), weekdays(&checked)) {
                (Some((minute, hour)), Some(field)) => {
                    Ok(ActionTime::new(kind, minute, hour, field))
                }
                (when, days) => {
                    let mut invalid = Vec::new();
                    if when.is_none() {
                        invalid.push(("time", keys::WEB_SYSTEM_SCHEDULES_TIME_ERROR));
                    }
                    if days.is_none() {
                        invalid.push(("day", keys::WEB_SYSTEM_SCHEDULES_DAYS_ERROR));
                    }
                    Err(Invalid::from(invalid))
                }
            },
            async |at, ctx| {
                let operation = schedules::plan_action(ctx, &name, at)?;
                let request = schedules::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
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
