//! `GET /ui/admin/scheduled`, the schedules table every change answers with, and the
//! answers the changes share.

use core::error::Error;

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use kcc_app::{
    permissions::Role,
    persist::StateStore,
    schedules::{
        ledger::RunsDocument,
        store::{ScheduleError, ScheduleStore},
    },
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};
use tokio::task::spawn_blocking;

use super::{Listed, rows};
use crate::{
    WebState,
    admin_shared::{Change, Tab, TabLink, forbidden, record, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{Caller, fragment_shell},
        outcome::Toast,
        respond,
    },
    table::view::TableView,
};

/// A failure the page answers with its error page.
pub(super) type Failure = Box<dyn Error + Send + Sync>;

/// The scheduled actions page.
#[derive(Template)]
#[template(path = "pages/admin_scheduled.html")]
struct ScheduledPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// Whether schedules can be added: a scheduler runs and routers are attached.
    can_add: bool,
    /// The table.
    region: Region,
}

localized!(ScheduledPage);

/// The schedules table, sent out of band after every change.
#[derive(Template)]
#[template(path = "partials/admin_scheduled_region.html")]
pub(super) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Whether it is sent out of band.
    oob: bool,
    /// Whether a scheduler runs in this process.
    running: bool,
    /// The schedules.
    table: TableView,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
}

localized!(Region);
fragment!(Region);

/// `GET /ui/admin/scheduled`.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    if state.admin().is_none() {
        return unavailable(Some(shell));
    }
    match region(&state, &user, Vec::new()).await {
        Ok(mut region) => {
            region.oob = false;
            errors::render(&ScheduledPage {
                tabs: tabs(user.role(), Tab::Scheduled),
                can_add: state.schedules().is_some() && state.fleet().is_some(),
                region,
                shell,
            })
        }
        Err(error) => errors::internal(&*error, shell),
    }
}

/// The schedule store of the attached administration services.
///
/// # Errors
///
/// When no administration services are attached.
pub(super) fn store(state: &WebState) -> Result<StateStore, Failure> {
    state
        .admin()
        .map(|admin| admin.state().clone())
        .ok_or_else(|| "administration services are not attached".into())
}

/// Runs `work` on the schedule store on a blocking thread.
///
/// # Errors
///
/// Missing administration services, the work's own error, or the blocking task's failure.
// cancel-safe: the work runs whole on its thread even if the future is dropped; only its result is
// lost.
pub(super) async fn on_store<T, F>(
    state: &WebState,
    work: F,
) -> Result<Result<T, ScheduleError>, Failure>
where
    T: Send + 'static,
    F: FnOnce(&ScheduleStore) -> Result<T, ScheduleError> + Send + 'static,
{
    let schedules = ScheduleStore::new(store(state)?);
    Ok(spawn_blocking(move || work(&schedules)).await?)
}

/// The schedules `role` sees, with their last runs.
///
/// # Errors
///
/// Missing administration services, state or blocking-task failures.
// cancel-safe: it only reads local state on a blocking thread.
async fn listed(state: &WebState, role: &Role) -> Result<Vec<Listed>, Failure> {
    let store = store(state)?;
    let reader = role.clone();
    let mut listed = spawn_blocking(move || -> Result<Vec<Listed>, Failure> {
        let schedules = ScheduleStore::new(store.clone()).list(&reader)?;
        let mut runs = store.read::<RunsDocument>()?.unwrap_or_default().schedules;
        Ok(schedules
            .into_iter()
            .map(|schedule| {
                let last = runs
                    .remove(&schedule.id)
                    .and_then(|history| history.runs.into_iter().last());
                Listed {
                    router_name: schedule.router.clone(),
                    schedule,
                    last,
                }
            })
            .collect())
    })
    .await??;
    for entry in &mut listed {
        entry.router_name = state.router_name(&entry.schedule.router);
    }
    Ok(listed)
}

/// The table for `user`, with `toasts`, sent out of band.
///
/// # Errors
///
/// Missing administration services, state or blocking-task failures.
// cancel-safe: it only reads local state on a blocking thread.
pub(super) async fn region(
    state: &WebState,
    user: &CurrentUser,
    toasts: Vec<Toast>,
) -> Result<Region, Failure> {
    let listed = listed(state, user.role()).await?;
    let running = state.schedules().is_some();
    Ok(Region {
        shell: fragment_shell(user.locale()),
        oob: true,
        running,
        table: rows::table(&listed, user.locale(), now(state), running),
        toasts,
    })
}

/// The audit parameters of a change of schedule `id` (`None` before it exists): its id,
/// its action kind and its router; never a client or a policy.
pub(super) fn params(id: Option<&str>, schedule: (&str, &str)) -> Value {
    let (kind, router) = schedule;
    json!({ "schedule": id, "action": kind, "router": router })
}

/// After a stored change: audits `action` on `target` with `params`, and answers with the
/// table read again and the `done` toast, closing the dialog it came from.
// NOT cancel-safe: the audit entry may be written after the future is dropped.
pub(super) async fn changed(
    state: &WebState,
    user: &CurrentUser,
    (action, target, params): (&'static str, &str, Value),
    done: MessageKey,
) -> Response {
    record(state, user, Change::done(action, target, params)).await;
    answer(
        state,
        user,
        Toast::success(user.locale(), done),
        StatusCode::OK,
    )
    .await
}

/// A refused change: audits `action` on `target` as `outcome`, and answers with the
/// table and the refusal's toast, as 422, closing the dialog it came from.
// NOT cancel-safe: the audit entry may be written after the future is dropped.
pub(super) async fn refused(
    state: &WebState,
    user: &CurrentUser,
    (action, target, outcome): (&'static str, &str, &'static str),
    message: MessageKey,
) -> Response {
    record(state, user, Change::refused(action, target, outcome)).await;
    let toast = Toast::error(user.locale(), message);
    answer(state, user, toast, StatusCode::UNPROCESSABLE_ENTITY).await
}

/// The table read again with `toast`, as `status`, closing the dialog.
// cancel-safe: it only reads local state on a blocking thread.
async fn answer(
    state: &WebState,
    user: &CurrentUser,
    toast: Toast,
    status: StatusCode,
) -> Response {
    match region(state, user, vec![toast]).await {
        Ok(region) => respond::region(&region, status, true),
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}

/// The answer to a store failure of a change: 404 for a schedule the role cannot see,
/// the audited 403, the refused limit, or the logged 500.
// NOT cancel-safe: a refusal's audit entry may be written after the future is dropped.
pub(super) async fn store_failed(
    state: &WebState,
    user: &CurrentUser,
    (action, target): (&'static str, &str),
    error: ScheduleError,
) -> Response {
    let shell = fragment_shell(user.locale());
    if matches!(error, ScheduleError::NotFound) {
        return errors::response(Kind::NotFound, shell);
    }
    if matches!(error, ScheduleError::Forbidden) {
        return forbidden(state, user, Change::refused(action, target, "forbidden")).await;
    }
    if matches!(
        error,
        ScheduleError::RouterLimit | ScheduleError::TotalLimit
    ) {
        let refusal = (action, target, "limit");
        return refused(state, user, refusal, keys::WEB_ADMIN_SCHEDULED_ERROR_LIMIT).await;
    }
    errors::internal(&error, shell)
}

/// The clock's time in Unix seconds, as the schedule store takes it.
pub(super) fn now(state: &WebState) -> i64 {
    i64::try_from(state.unix_seconds()).unwrap_or(i64::MAX)
}
