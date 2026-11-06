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
use kcc_catalog::Risk;
use kcc_domain::services;

use super::{
    services::{MANAGEMENT, Viewer, known},
    shared::{answer, forbidden, merged, missing, shown_query, value, with_query},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::{Confirmation, Resubmit},
        failure::plan_failure,
        family::Family,
        gate::{allowed, operation_permissions},
        outcome::Outcome,
        respond::Answer,
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
        Some("true") => true,
        Some("false") => false,
        Some(_) | None => {
            action.abandon("validation_failed").await;
            return Err(missing());
        }
    };
    if !known(&domain.catalog).contains(&name) {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let risk = if MANAGEMENT.contains(&name.as_str()) {
        Risk::Management
    } else {
        Risk::Write
    };
    if !allowed(
        &user,
        &router,
        &operation_permissions(Permission::Write, risk),
    ) {
        action.abandon("forbidden").await;
        return Err(forbidden(locale));
    }
    let planned = services::plan_service(&domain, &name, wanted)
        .and_then(|operation| services::change_request(&operation));
    let request = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            let failure = plan_failure(Family::Changes, locale, &error);
            let outcome =
                Outcome::invalid(Family::Changes, locale, vec![failure.message().to_owned()]);
            return Ok(answer(outcome, None, locale));
        }
    };
    let on = if wanted { "true" } else { "false" };
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/services/toggle"),
            &[("name", &name), ("on", on)],
        ),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(risk, &Confirmation::from_pairs(&pairs), resubmit) {
        return Ok(prompt);
    }
    let outcome = action.run(risk, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&domain)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, locale))
}
