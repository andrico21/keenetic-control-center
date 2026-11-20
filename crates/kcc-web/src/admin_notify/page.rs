//! `GET /ui/admin/notifications` and the answers every change of the page shares.

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde_json::Value;

use super::{
    store::{Failure, Seen, seen},
    view::Region,
};
use crate::{
    WebState,
    admin_shared::{Change, Tab, TabLink, record, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{Caller, fragment_shell},
        outcome::Toast,
        respond,
    },
};

/// What the audit log names as the target of every change of the page.
const TARGET: &str = "telegram";

/// The notifications page.
#[derive(Template)]
#[template(path = "pages/admin_notify.html")]
struct NotifyPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// Every panel.
    region: Region,
}

localized!(NotifyPage);

/// `GET /ui/admin/notifications`.
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
    match seen(&state).await {
        Ok(seen) => errors::render(&NotifyPage {
            tabs: tabs(user.role(), Tab::Notifications),
            region: region(&state, user.locale(), &seen).inline(),
            shell,
        }),
        Err(error) => errors::internal(&*error, shell),
    }
}

/// The region of `seen` in `locale`, sent out of band.
pub(super) fn region(state: &WebState, locale: Locale, seen: &Seen) -> Region {
    let api_url = state
        .admin()
        .and_then(|admin| admin.server().telegram_api());
    Region::new(locale, seen, api_url)
}

/// The region read again in `locale`.
///
/// # Errors
///
/// State or blocking-task failures.
// cancel-safe: it only reads local state on a blocking thread.
pub(super) async fn fresh(state: &WebState, locale: Locale) -> Result<Region, Failure> {
    Ok(region(state, locale, &seen(state).await?))
}

/// After a stored change: asks the running notifier to reload, audits `action` with
/// `params`, and answers with the region read again and the `done` toast.
// NOT cancel-safe: the audit entry may be written after the future is dropped.
pub(super) async fn changed(
    state: &WebState,
    user: &CurrentUser,
    (action, params): (&'static str, Value),
    done: MessageKey,
) -> Response {
    if let Some(control) = state.notify() {
        control.reload();
    }
    record(state, user, Change::done(action, TARGET, params)).await;
    match fresh(state, user.locale()).await {
        Ok(mut region) => {
            region.toast(Toast::success(user.locale(), done));
            errors::render(&region)
        }
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}

/// The region read again with `fill` applied, as 422.
// cancel-safe: it only reads local state on a blocking thread.
pub(super) async fn refused<F>(state: &WebState, locale: Locale, fill: F) -> Response
where
    F: FnOnce(&mut Region),
{
    match fresh(state, locale).await {
        Ok(mut region) => {
            fill(&mut region);
            respond::unprocessable(&region)
        }
        Err(error) => errors::internal(&*error, fragment_shell(locale)),
    }
}

/// The answer to a change of a chat the settings do not hold.
pub(super) fn missing() -> Response {
    StatusCode::NOT_FOUND.into_response()
}
