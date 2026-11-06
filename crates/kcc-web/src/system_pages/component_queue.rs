//! The component queue of the components page: Check for updates, Install and Remove.
//!
//! Each is a write through the change workflow; nothing reaches the firmware until the
//! commit (`component_commit`). A component or an action the list does not offer is
//! refused before anything is sent.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::components::{self, QueueAction};
use kcc_i18n::locale::Locale;

use super::{
    components::{Viewer, read},
    shared::{answer, merged, missing, shown_query, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation, change::Change, failure::plan_failure, family::Family, outcome::Outcome,
        respond::Answer,
    },
};

/// Checking for updates, audited as `web.components_check`.
const CHECK: Operation = Operation::write(
    &components::DESCRIPTOR,
    "check_update",
    "web.components_check",
);

/// `POST /ui/r/{router}/system/components/check`: asks the router to look for updates.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn check(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = CHECK.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let planned = components::plan_check_update(&domain)
        .and_then(|operation| components::change_request(&operation));
    let request = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            let failure = plan_failure(Family::Changes, locale, &error);
            return Ok(invalid(failure.message(), locale));
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

/// `POST /ui/r/{router}/system/components/queue?name=&action=install|remove`: queues one
/// component change.
///
/// # Errors
///
/// Answers 404 for a component or an action the list does not offer, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn queue(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let (write, wanted) = match value(&pairs, "action") {
        Some("install") => ("install", QueueAction::Install),
        Some("remove") => ("remove", QueueAction::Remove),
        Some(_) | None => return Err(missing()),
    };
    let audit = if wanted == QueueAction::Install {
        "web.components_install"
    } else {
        "web.components_remove"
    };
    let action = Operation::write(&components::DESCRIPTOR, write, audit)
        .open(&state, &user, &router)
        .await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    let offered = read(&domain)
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|component| component.name() == name && component.action() == Some(wanted));
    if !offered {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let planned = components::plan_queue(&domain, wanted, &name)
        .and_then(|operation| components::change_request(&operation));
    let request = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            let failure = plan_failure(Family::Changes, locale, &error);
            return Ok(invalid(failure.message(), locale));
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

/// The answer to a change refused before anything was sent.
fn invalid(problem: &str, locale: Locale) -> Response {
    let outcome = Outcome::invalid(Family::Changes, locale, vec![problem.to_owned()]);
    answer(outcome, None, locale)
}
