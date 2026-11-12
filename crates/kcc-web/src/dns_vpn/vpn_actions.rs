//! The VPN row and panel actions: a connection on or off, a connection deleted after its
//! name is typed, a server's service on or off.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{
    vpn_clients::{self, VpnClientChange},
    vpn_servers::{self, VpnServerChange, VpnServerService},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    check, flow,
    form::Values,
    screen::{Answered, missing},
    vpn_checks::Planned,
    vpn_pages::{Spot, region},
    vpn_read::exists,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        action::{Action, Operation},
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        outcome::Outcome,
        respond::{self, Answer},
        typed_name::{TypedNameDialog, TypedNameForm},
    },
};

/// A connection on or off, audited as `web.vpn_state`.
const STATE: Operation = Operation::write(&vpn_clients::DESCRIPTOR, "enabled", "web.vpn_state");

/// A connection deleted, audited as `web.vpn_delete`.
const DELETE: Operation = Operation::write(&vpn_clients::DESCRIPTOR, "delete", "web.vpn_delete");

/// The connection a delete dialog names.
#[derive(Debug, Deserialize)]
pub(crate) struct TunnelQuery {
    /// The connection's name.
    #[serde(default)]
    tunnel: String,
}

/// `POST /ui/r/{router}/vpn/state`: turns the connection `tunnel` on (`enabled=on`) or off.
///
/// # Errors
///
/// Answers 404 for malformed fields, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn switch(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let values = Values::new(pairs);
    let opened = STATE.open(&state, &user, &router).await?;
    let (Some(name), Some(enabled)) = (check::object(values.get("tunnel")), on(&values)) else {
        opened.abandon("validation_failed").await;
        return Err(missing());
    };
    let action = known(opened, &name).await?;
    let planned = Planned::Clients(vec![VpnClientChange::Enabled { name, enabled }]);
    let reply = Reply::new(&headers, &user, Spot::Connections);
    Ok(run(action, planned, reply).await)
}

/// `POST /ui/r/{router}/vpn/service`: turns a VPN server's service on or off.
///
/// # Errors
///
/// Answers 404 for an unknown server, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn service(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let values = Values::new(pairs);
    let (service, operation) = match values.get("service") {
        "vpn" => (VpnServerService::Vpn, "vpn_service"),
        "sstp" => (VpnServerService::Sstp, "sstp_service"),
        "oc" => (VpnServerService::OpenConnect, "openconnect_service"),
        "ipsec" => (VpnServerService::Ipsec, "ipsec_service"),
        _ => return Err(missing()),
    };
    let write = Operation::write(&vpn_servers::DESCRIPTOR, operation, "web.vpn_service");
    let action = write.open(&state, &user, &router).await?;
    let Some(enabled) = on(&values) else {
        action.abandon("validation_failed").await;
        return Err(missing());
    };
    let planned = Planned::Servers(vec![VpnServerChange::Service { service, enabled }]);
    Ok(run(action, planned, Reply::new(&headers, &user, Spot::Servers)).await)
}

/// `GET /ui/r/{router}/vpn/delete?tunnel=`: asks for the connection's name.
///
/// # Errors
///
/// Answers 404 for a malformed name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TunnelQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let name = check::object(&query.tunnel).ok_or_else(missing)?;
    Ok(errors::render(&confirmation(
        action.locale(),
        &router,
        &name,
    )))
}

/// `POST /ui/r/{router}/vpn/delete`: deletes the connection once its name is typed.
///
/// # Errors
///
/// Answers the dialog again (422) when the typed name does not match, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let opened = DELETE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let Some(name) = check::object(form.name()) else {
        opened.abandon("validation_failed").await;
        return Err(missing());
    };
    let action = known(opened, &name).await?;
    if !form.confirmed() {
        action.abandon("validation_failed").await;
        let mut dialog = confirmation(locale, &router, &name);
        dialog.set_error(tr(locale, keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
    }
    let planned = Planned::Clients(vec![VpnClientChange::Delete { name }]);
    let answer = run(
        action,
        planned,
        Reply::new(&headers, &user, Spot::Connections),
    )
    .await;
    Ok(respond::retarget(answer, "#page-outcome"))
}

/// `action` again when `name` is one of the router's VPN connections.
///
/// These routes never switch or delete another interface.
///
/// # Errors
///
/// Answers the audited refusal: 404 for another name, the failure when the connections
/// cannot be read.
// NOT cancel-safe: an abandoned append may still be written.
async fn known<'call>(action: Action<'call>, name: &str) -> Result<Action<'call>, Answer> {
    let locale = action.locale();
    let ctx = action.context().await?;
    match exists(&ctx, name).await {
        Ok(true) => Ok(action),
        Ok(false) => {
            action.abandon("validation_failed").await;
            Err(missing())
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            Err(Answered::new(Outcome::failed(failure), locale)
                .respond()
                .into())
        }
    }
}

/// The typed-name confirmation deleting the connection `name` of `router`.
fn confirmation(locale: Locale, router: &str, name: &str) -> TypedNameDialog {
    TypedNameDialog::new(
        fragment_shell(locale),
        format!("/ui/r/{router}/vpn/delete"),
        name,
        (keys::WEB_VPN_DELETE_TITLE, keys::WEB_VPN_DELETE_TEXT),
    )
}

/// The field `enabled`: `on` or `off`.
fn on(values: &Values) -> Option<bool> {
    match values.get("enabled") {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// Where an action's answer goes: the page that sent it, its user and the region to read
/// back.
struct Reply<'request> {
    /// Request headers, for the page's table query.
    headers: &'request HeaderMap,
    /// The signed-in user.
    user: &'request CurrentUser,
    /// The region read back.
    spot: Spot,
}

impl<'request> Reply<'request> {
    /// The answer to `user` on the page of `headers`, reading `spot` back.
    const fn new(headers: &'request HeaderMap, user: &'request CurrentUser, spot: Spot) -> Self {
        Self {
            headers,
            user,
            spot,
        }
    }
}

/// Plans `planned` for `action`, runs it and answers as `reply` says.
// NOT cancel-safe: see `Action::run`.
async fn run(action: Action<'_>, changes: Planned, reply: Reply<'_>) -> Response {
    let locale = action.locale();
    let ctx = match action.context().await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let request_plan = match changes.request(&ctx).await {
        Ok(request) => request,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Answered::new(Outcome::failed(failure), locale).respond();
        }
    };
    if !request_plan.allowed(reply.user, action.router()) {
        action.abandon("forbidden").await;
        return errors::response(errors::Kind::Forbidden, fragment_shell(locale));
    }
    let spot = reply.spot;
    let viewer = spot
        .viewer(&ctx, reply.user, action.router())
        .with_query(flow::shown_query(reply.headers));
    let (request, risk) = request_plan.into_parts();
    flow::apply(action, request, risk, async || {
        region(&ctx, &spot, &viewer).await
    })
    .await
    .respond()
}
