//! Turning one service on or off from the services page.
//!
//! An ordinary service is a write; HTTP, SSH and Telnet carry management access, so the
//! handler raises the change to management risk: it needs `Destructive` too (403
//! otherwise), asks first with the kit's dialog explaining the fail-safe timer, and runs
//! inside that timer.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::permissions::Permission;
use kcc_domain::{configuration::SafetyNet, services};
use kcc_i18n::keys;

use super::{
    services::{Viewer, known},
    shared::{NoDialog, forbidden, merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        gate::allowed,
        request::{Params, missing, shown_query, with_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// Turning a service on or off, audited as `web.system_service`.
const SET: Operation = Operation::write(&services::DESCRIPTOR, "set_service", "web.system_service");

/// `POST /ui/r/{router}/system/services/toggle?name=&on=`: turns one service on or off;
/// a management service asks first and runs inside the fail-safe timer.
///
/// # Errors
///
/// Answers 404 for a service the catalog does not know, 403 when the role may not take
/// the change's risk, and what the kit answers when the router or the permission is
/// missing.
// NOT cancel-safe: a transmitted service change may precede read-back and timer cleanup.
pub(crate) async fn toggle(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = SET.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    let wanted = match value(&pairs, "on") {
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) | None => None,
    };
    if wanted.is_some() {
        if !known(&domain.catalog).contains(&name) {
            action.abandon("not_found").await;
            return Err(missing());
        }
        let risk = services::service_risk(&name);
        if !allowed(
            &user,
            &router,
            &SafetyNet::required(Permission::Write, risk),
        ) {
            action.abandon("forbidden").await;
            return Err(forbidden(locale));
        }
    }
    let on = if wanted == Some(true) {
        "true"
    } else {
        "false"
    };
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/services/toggle"),
            &[("name", &name), ("on", on)],
        ),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &Params::of(pairs), NoDialog)
        .confirming_planned(resubmit)
        .submit(
            |_params| wanted.ok_or_else(|| Invalid::at("on", keys::WEB_DNS_ERROR_CHOICE)),
            async |enabled, ctx| {
                let operation = services::plan_service(ctx, &name, enabled)?;
                let request = services::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
}
