//! Pausing, resuming and deleting a schedule.
//!
//! `POST /ui/admin/scheduled/pause` pauses by hand, `.../resume` resumes once the scheduler
//! said the action can run (the clicker becomes the owner), and `GET`/`POST
//! /ui/admin/scheduled/delete?id=` deletes once confirmed.

use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::schedules::model::{Owner, Schedule};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::Value;

use super::{
    ScheduleDraft, ScheduleId, ScheduleRefusal,
    page::{changed, now, on_store, params, refused, store_failed},
    rows::named_id,
    text,
};
use crate::{
    WebState,
    admin_shared::unavailable,
    authz::CurrentUser,
    errors,
    page_kit::{
        confirm::{Confirmation, Dialog, Resubmit, Words},
        context::fragment_shell,
        respond::Answer,
    },
};

/// `POST /ui/admin/scheduled/pause`: pauses a schedule by hand; its owner stays.
// NOT cancel-safe: the pause is written on a blocking thread that finishes even if the future is
// dropped, leaving it unaudited.
pub(crate) async fn pause(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<ScheduleId>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let (role, id, at) = (user.role().clone(), form.id.clone(), now(&state));
    match on_store(&state, move |store| store.pause(&role, &id, at)).await {
        Ok(Ok(schedule)) => {
            let audited = audited(&schedule);
            let change = ("web.schedule_pause", schedule.id.as_str(), audited);
            changed(&state, &user, change, keys::WEB_ADMIN_SCHEDULED_PAUSED_DONE).await
        }
        Ok(Err(error)) => {
            store_failed(&state, &user, ("web.schedule_pause", &form.id), error).await
        }
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}

/// `POST /ui/admin/scheduled/resume`: resumes a schedule with the clicker as its owner,
/// once the scheduler said its action can run; slots before now never fire.
// NOT cancel-safe: the resume is written on a blocking thread that finishes even if the future is
// dropped, leaving it unaudited.
pub(crate) async fn resume(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<ScheduleId>,
) -> Response {
    const ACTION: &str = "web.schedule_resume";
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let schedule = match visible(&state, &user, (ACTION, &form.id)).await {
        Ok(schedule) => schedule,
        Err(answer) => return answer.into_response(),
    };
    let checked = match state.schedules() {
        Some(control) => {
            let draft = ScheduleDraft::new(schedule.router.clone(), schedule.action.clone());
            control.check(user.role(), &draft).await
        }
        None => Err(ScheduleRefusal::Unavailable),
    };
    if let Err(refusal) = checked {
        let refusal_of = (ACTION, form.id.as_str(), refusal.code());
        return refused(&state, &user, refusal_of, text::refusal(refusal)).await;
    }
    let (role, id, at) = (user.role().clone(), form.id.clone(), now(&state));
    let owner = Owner::Web {
        username: user.username().to_owned(),
    };
    match on_store(&state, move |store| store.resume(&role, &id, owner, at)).await {
        Ok(Ok(resumed)) => {
            let change = (ACTION, resumed.id.as_str(), audited(&resumed));
            changed(&state, &user, change, keys::WEB_ADMIN_SCHEDULED_RESUMED).await
        }
        Ok(Err(error)) => store_failed(&state, &user, (ACTION, &form.id), error).await,
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}

/// `GET /ui/admin/scheduled/delete?id=`: the confirmation.
// NOT cancel-safe: a refusal's audit entry may be written after the future is dropped; otherwise it
// only reads local state on a blocking thread.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<ScheduleId>,
) -> Response {
    if state.admin().is_none() {
        return unavailable(None);
    }
    match visible(&state, &user, ("web.schedule_delete", &query.id)).await {
        Ok(schedule) => confirmation(&schedule, user.locale()).show(),
        Err(answer) => answer.into_response(),
    }
}

/// `POST /ui/admin/scheduled/delete?id=`: deletes a schedule and its run history once
/// confirmed; unconfirmed, it asks.
// NOT cancel-safe: the deletion is written on a blocking thread that finishes even if the future is
// dropped, leaving it unaudited.
pub(crate) async fn delete(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<ScheduleId>,
    Form(confirmed): Form<Confirmation>,
) -> Response {
    const ACTION: &str = "web.schedule_delete";
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let schedule = match visible(&state, &user, (ACTION, &query.id)).await {
        Ok(schedule) => schedule,
        Err(answer) => return answer.into_response(),
    };
    if !confirmed.confirmed() {
        return confirmation(&schedule, user.locale()).show();
    }
    let (role, id) = (user.role().clone(), query.id.clone());
    match on_store(&state, move |store| store.delete(&role, &id)).await {
        Ok(Ok(())) => {
            let change = (ACTION, schedule.id.as_str(), audited(&schedule));
            changed(&state, &user, change, keys::WEB_ADMIN_SCHEDULED_DELETED).await
        }
        Ok(Err(error)) => store_failed(&state, &user, (ACTION, &query.id), error).await,
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}

/// Schedule `id` when `user` may manage it.
///
/// # Errors
///
/// The answer to the store's refusal of `action` (see `store_failed`), or the logged 500.
// NOT cancel-safe: a refusal's audit entry may be written after the future is dropped; otherwise it
// only reads local state on a blocking thread.
pub(super) async fn visible(
    state: &WebState,
    user: &CurrentUser,
    (action, id): (&'static str, &str),
) -> Result<Schedule, Answer> {
    let (role, wanted) = (user.role().clone(), id.to_owned());
    match on_store(state, move |store| store.get(&role, &wanted)).await {
        Ok(Ok(schedule)) => Ok(schedule),
        Ok(Err(error)) => Err(store_failed(state, user, (action, id), error).await.into()),
        Err(error) => Err(errors::internal(&*error, fragment_shell(user.locale())).into()),
    }
}

/// The audit parameters of `schedule`.
pub(super) fn audited(schedule: &Schedule) -> Value {
    params(
        Some(&schedule.id),
        (text::kind(&schedule.action), &schedule.router),
    )
}

/// The deletion's confirmation of `schedule` in `locale`.
fn confirmation(schedule: &Schedule, locale: Locale) -> Dialog {
    let mut args = FluentArgs::new();
    args.set("name", schedule.name.as_str().to_owned());
    let words = Words::new(
        tr(locale, keys::WEB_ADMIN_SCHEDULED_DELETE_TITLE, Some(&args)),
        tr(locale, keys::WEB_ADMIN_SCHEDULED_DELETE_TEXT, None),
        tr(locale, keys::COMMON_DELETE, None),
    );
    let action = named_id("/ui/admin/scheduled/delete", &schedule.id);
    Dialog::new(locale, words, Resubmit::new(action, "#page-outcome"))
}
