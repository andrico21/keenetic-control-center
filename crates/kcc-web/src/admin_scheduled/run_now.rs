//! `GET`/`POST /ui/admin/scheduled/run-now?id=`: runs a schedule now.
//!
//! The run goes through the running scheduler once confirmed (a restart with the router's
//! name typed) and goes on in the background; a busy router does not refuse it: the run
//! is admitted and ends `Skipped router_busy`.

use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::schedules::model::{Action, Owner, Schedule};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    ScheduleId, ScheduleRefusal,
    page::{changed, refused},
    rows::named_id,
    text,
    toggle::{audited, visible},
};
use crate::{
    WebState,
    admin_shared::unavailable,
    authz::CurrentUser,
    page_kit::confirm::{Ask, Confirmation, Dialog, Resubmit, Typed, Words},
};

/// The audit action of a run-now.
const ACTION: &str = "web.schedule_run_now";

/// `GET /ui/admin/scheduled/run-now?id=`: the confirmation.
// NOT cancel-safe: a refusal's audit entry may be written after the future is dropped; otherwise it
// only reads local state on a blocking thread.
pub(crate) async fn run_dialog(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<ScheduleId>,
) -> Response {
    if state.admin().is_none() || state.schedules().is_none() {
        return unavailable(None);
    }
    match visible(&state, &user, (ACTION, &query.id)).await {
        Ok(schedule) => confirmation(&schedule, user.locale(), false).show(),
        Err(answer) => answer.into_response(),
    }
}

/// `POST /ui/admin/scheduled/run-now?id=`: starts the run once confirmed; unconfirmed,
/// or with a restart's router name mistyped, it asks again.
// NOT cancel-safe: the scheduler may admit the run, and its audit entry may be written, after the
// future is dropped.
pub(crate) async fn run_now(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<ScheduleId>,
    Form(confirmed): Form<Confirmation>,
) -> Response {
    if state.admin().is_none() {
        return unavailable(None);
    }
    let schedule = match visible(&state, &user, (ACTION, &query.id)).await {
        Ok(schedule) => schedule,
        Err(answer) => return answer.into_response(),
    };
    let restart = schedule.action == Action::Reboot;
    let named = !restart || confirmed.name() == Some(schedule.router.as_str());
    if !confirmed.confirmed() || !named {
        let mistyped = confirmed.confirmed() && !named;
        return confirmation(&schedule, user.locale(), mistyped).show();
    }
    let actor = Owner::Web {
        username: user.username().to_owned(),
    }
    .to_string();
    let started = match state.schedules() {
        Some(control) => control.run_now(user.role(), &actor, &schedule.id).await,
        None => Err(ScheduleRefusal::Unavailable),
    };
    match started {
        Ok(_admitted) => {
            let change = (ACTION, schedule.id.as_str(), audited(&schedule));
            changed(
                &state,
                &user,
                change,
                keys::WEB_ADMIN_SCHEDULED_RUN_ADMITTED,
            )
            .await
        }
        Err(refusal) => {
            let refusal_of = (ACTION, schedule.id.as_str(), refusal.code());
            refused(&state, &user, refusal_of, text::refusal(refusal)).await
        }
    }
}

/// The run-now confirmation of `schedule` in `locale`; a restart asks for the router's
/// name, saying so when `mistyped`.
fn confirmation(schedule: &Schedule, locale: Locale, mistyped: bool) -> Dialog {
    let mut args = FluentArgs::new();
    args.set("name", schedule.name.as_str().to_owned());
    let restart = schedule.action == Action::Reboot;
    let words = Words::new(
        tr(locale, keys::WEB_ADMIN_SCHEDULED_RUN_TITLE, Some(&args)),
        tr(
            locale,
            if restart {
                keys::WEB_ADMIN_SCHEDULED_RUN_REBOOT_TEXT
            } else {
                keys::WEB_ADMIN_SCHEDULED_RUN_TEXT
            },
            None,
        ),
        tr(locale, keys::WEB_ADMIN_SCHEDULED_RUN, None),
    );
    let action = named_id("/ui/admin/scheduled/run-now", &schedule.id);
    let dialog = Dialog::new(locale, words, Resubmit::new(action, "#page-outcome"));
    if restart {
        let error = if mistyped {
            tr(locale, keys::WEB_ADMIN_SCHEDULED_ERROR_CONFIRM, None)
        } else {
            String::new()
        };
        dialog.asking(Ask::Typed(Typed::router(locale).with_error(error)))
    } else {
        dialog
    }
}
