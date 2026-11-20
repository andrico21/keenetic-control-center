//! `GET /ui/admin/scheduled/new` and `.../edit`, the dialogs, and `POST
//! /ui/admin/scheduled` and `.../edit`, which store a schedule once the scheduler said it
//! can run; the clicker becomes its owner.

use axum::{
    Form,
    extract::{Query, State},
    response::Response,
};
use kcc_app::schedules::{
    model::{NewSchedule, Owner, Schedule},
    store::ScheduleError,
};
use kcc_i18n::{bundle::tr, keys};

use super::{
    ScheduleDraft, ScheduleRefusal,
    dialog::{editor, router_ids, shown},
    form::{Errors, Typed, parse},
    page::{Failure, changed, now, on_store, params, store_failed},
    text,
};
use crate::{
    WebState,
    admin_shared::{Change, record, unavailable},
    authz::CurrentUser,
    errors,
    page_kit::{context::fragment_shell, request::last},
};

/// The dialog's query or form: its fields as `name=value` pairs.
type Pairs = Vec<(String, String)>;

/// `GET /ui/admin/scheduled/new`: the add dialog, or the dialog shown again with the
/// fields in the query after its router or action changed.
// NOT cancel-safe: it may sign in to the router to read the dialog's lists, and a sign-in dropped
// mid-way can leave an orphaned router session.
pub(crate) async fn new_dialog(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(pairs): Query<Pairs>,
) -> Response {
    let Some(admin) = state.admin().filter(|_admin| state.schedules().is_some()) else {
        return unavailable(None);
    };
    let routers = match router_ids(&state, user.role()).await {
        Ok(routers) => routers,
        Err(error) => return errors::internal(&*error, fragment_shell(user.locale())),
    };
    let typed = if last(&pairs, "router").is_some() {
        Typed::from_pairs(&pairs)
    } else {
        Typed::fresh(
            admin.server().default_timezone(),
            routers.first().map(String::as_str),
        )
    };
    errors::render(&editor(&state, &user, (routers, typed), Errors::default()).await)
}

/// `GET /ui/admin/scheduled/edit?id=`: the edit dialog, or the dialog shown again with the
/// fields in the query after its router or action changed.
// NOT cancel-safe: as `new_dialog`.
pub(crate) async fn edit_dialog(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(pairs): Query<Pairs>,
) -> Response {
    if state.admin().is_none() || state.schedules().is_none() {
        return unavailable(None);
    }
    let locale = user.locale();
    let typed = if last(&pairs, "router").is_some() {
        Typed::from_pairs(&pairs)
    } else {
        let id = last(&pairs, "id").unwrap_or_default().to_owned();
        let reader = user.role().clone();
        match on_store(&state, move |store| store.get(&reader, &id)).await {
            Ok(Ok(schedule)) => Typed::of(&schedule),
            Ok(Err(error)) => {
                let target = last(&pairs, "id").unwrap_or_default();
                return store_failed(&state, &user, ("web.schedule_update", target), error).await;
            }
            Err(error) => return errors::internal(&*error, fragment_shell(locale)),
        }
    };
    let routers = match router_ids(&state, user.role()).await {
        Ok(routers) => routers,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    errors::render(&editor(&state, &user, (routers, typed), Errors::default()).await)
}

/// `POST /ui/admin/scheduled`: adds a schedule owned by the clicker.
// NOT cancel-safe: the schedule is stored on a blocking thread that finishes even if the future is
// dropped, leaving it unaudited.
pub(crate) async fn create(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(pairs): Form<Pairs>,
) -> Response {
    let mut typed = Typed::from_pairs(&pairs);
    typed.forget_id();
    submit(&state, &user, typed).await
}

/// `POST /ui/admin/scheduled/edit`: replaces a schedule's fields; the clicker becomes its
/// owner.
// NOT cancel-safe: as `create`.
pub(crate) async fn update(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(pairs): Form<Pairs>,
) -> Response {
    let typed = Typed::from_pairs(&pairs);
    if typed.id().is_empty() {
        return errors::response(errors::Kind::NotFound, fragment_shell(user.locale()));
    }
    submit(&state, &user, typed).await
}

/// Checks `typed`, asks the scheduler, stores the schedule and answers with the table;
/// a refusal shows the dialog again with its message.
// NOT cancel-safe: as `create`.
async fn submit(state: &WebState, user: &CurrentUser, typed: Typed) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let action = if typed.id().is_empty() {
        "web.schedule_create"
    } else {
        "web.schedule_update"
    };
    let routers = match router_ids(state, user.role()).await {
        Ok(routers) => routers,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let new = match parse::schedule(&typed, &routers, locale) {
        Ok(new) => new,
        Err(field_errors) => return shown(state, user, (routers, typed), *field_errors).await,
    };
    let target = if typed.id().is_empty() {
        new.router.clone()
    } else {
        typed.id().to_owned()
    };
    let checked = match state.schedules() {
        Some(control) => {
            let draft = ScheduleDraft::new(new.router.clone(), new.action.clone());
            control.check(user.role(), &draft).await
        }
        None => Err(ScheduleRefusal::Unavailable),
    };
    let source = match checked {
        Ok(source) => source,
        Err(refusal) => {
            record(
                state,
                user,
                Change::refused(action, &target, refusal.code()),
            )
            .await;
            let mut errors = Errors::default();
            errors.refuse(tr(locale, text::refusal(refusal), None));
            return shown(state, user, (routers, typed), errors).await;
        }
    };
    let sourced = match source {
        Some(router) => new.with_preset_source(&router),
        None => new,
    };
    match store(state, user, (typed.id(), sourced)).await {
        Ok(Ok(schedule)) => {
            let audited = params(
                Some(&schedule.id),
                (text::kind(&schedule.action), &schedule.router),
            );
            let done = if typed.id().is_empty() {
                keys::WEB_ADMIN_SCHEDULED_CREATED
            } else {
                keys::WEB_ADMIN_SCHEDULED_UPDATED
            };
            changed(state, user, (action, &schedule.id, audited), done).await
        }
        Ok(Err(error)) => {
            refused_by_store(state, user, (action, &target), (routers, typed), error).await
        }
        Err(error) => errors::internal(&*error, fragment_shell(locale)),
    }
}

/// Creates the schedule `new`, or replaces schedule `id`'s fields with it, owned by `user`.
///
/// # Errors
///
/// Missing administration services or blocking-task failures; the store's refusal inside.
// NOT cancel-safe: the store writes on a blocking thread that finishes even if the future is
// dropped.
async fn store(
    state: &WebState,
    user: &CurrentUser,
    (id, new): (&str, NewSchedule),
) -> Result<Result<Schedule, ScheduleError>, Failure> {
    let role = user.role().clone();
    let owner = Owner::Web {
        username: user.username().to_owned(),
    };
    let at = now(state);
    let edited = id.to_owned();
    on_store(state, move |store| {
        if edited.is_empty() {
            store.create(&role, new, owner, at)
        } else {
            store.update(&role, &edited, new, owner, at)
        }
    })
    .await
}

/// The dialog shown again after the store refused: a taken name or a role without the
/// action's permissions, a limit, or another failure's answer.
// NOT cancel-safe: the refusal's audit entry may be written after the future is dropped.
async fn refused_by_store(
    state: &WebState,
    user: &CurrentUser,
    (action, target): (&'static str, &str),
    shown_with: (Vec<String>, Typed),
    error: ScheduleError,
) -> Response {
    let locale = user.locale();
    let mut errors = Errors::default();
    let outcome = if matches!(error, ScheduleError::DuplicateName) {
        errors.refuse_name(tr(locale, keys::WEB_ADMIN_SCHEDULED_ERROR_NAME_TAKEN, None));
        "duplicate_name"
    } else if matches!(error, ScheduleError::Forbidden) {
        errors.refuse(tr(locale, keys::WEB_SCHEDULED_REFUSED_FORBIDDEN, None));
        "forbidden"
    } else if matches!(
        error,
        ScheduleError::RouterLimit | ScheduleError::TotalLimit
    ) {
        errors.refuse(tr(locale, keys::WEB_ADMIN_SCHEDULED_ERROR_LIMIT, None));
        "limit"
    } else {
        return store_failed(state, user, (action, target), error).await;
    };
    record(state, user, Change::refused(action, target, outcome)).await;
    shown(state, user, shown_with, errors).await
}
