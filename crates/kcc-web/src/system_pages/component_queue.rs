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
use kcc_domain::{
    ChangeOp, Result as DomainResult,
    components::{self, QueueAction},
};

use super::{
    components::{Viewer, read},
    shared::{NoDialog, merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        request::{Params, missing, shown_query},
        respond::Answer,
        submit::{Planned, Submission},
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
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &Params::default(), NoDialog)
        .submit(
            |_params| Ok(()),
            async |(), ctx| planned(components::plan_check_update(ctx)?),
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
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
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &Params::default(), NoDialog)
        .submit(
            |_params| Ok(()),
            async |(), ctx| planned(components::plan_queue(ctx, wanted, &name)?),
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
}

/// The components plan `operation` as the change that runs it.
///
/// # Errors
///
/// Returns the catalog's findings.
fn planned(operation: ChangeOp) -> DomainResult<Planned> {
    let request = components::change_request(&operation)?;
    Ok(Planned::of(&[operation], Change::Cli(request)))
}
